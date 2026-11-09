"""Restore DaC-managed Splunk saved searches from a pre-deployment snapshot."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

MANAGED_PREFIX = "DaC - "
RESTORE_FIELDS = [
    "search",
    "description",
    "disabled",
    "is_scheduled",
    "cron_schedule",
    "dispatch.earliest_time",
    "dispatch.latest_time",
    "alert_type",
    "alert_comparator",
    "alert_threshold",
    "alert.track",
]


def env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def check_target(url: str) -> str:
    if not url or urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
        raise SystemExit("SPLUNK_MANAGEMENT_URL must be an https:// management URL")
    return url.rstrip("/")


def stringify(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return ""
    return str(value)


def boolish(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalized_field(field: str, value):
    if field in {"disabled", "is_scheduled", "alert.track"}:
        return boolish(value)
    return stringify(value).strip()


def load_snapshot(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"Snapshot not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise SystemExit("Unsupported rollback snapshot schema")
    searches = data.get("searches")
    if not isinstance(searches, list) or not searches:
        raise SystemExit("Rollback snapshot contains no saved searches")
    for item in searches:
        name = str(item.get("name", ""))
        if not name.startswith(MANAGED_PREFIX):
            raise SystemExit(f"Refusing unmanaged saved search in snapshot: {name!r}")
        fields = item.get("fields")
        if not isinstance(fields, dict) or not fields.get("search"):
            raise SystemExit(f"Snapshot entry is missing search content: {name}")
    return data


def get_all_managed(session: requests.Session, namespace: str) -> dict[str, dict]:
    response = session.get(
        namespace,
        params={"output_mode": "json", "count": 0},
        timeout=30,
    )
    response.raise_for_status()
    return {
        str(entry["name"]): entry
        for entry in response.json().get("entry", [])
        if str(entry.get("name", "")).startswith(MANAGED_PREFIX)
    }


def restore_one(
    session: requests.Session,
    namespace: str,
    name: str,
    fields: dict,
) -> str:
    item_url = f"{namespace}/{quote(name, safe='')}"
    check = session.get(item_url, params={"output_mode": "json"}, timeout=20)
    if check.status_code not in (200, 404):
        check.raise_for_status()

    data = {
        field: stringify(fields.get(field))
        for field in RESTORE_FIELDS
        if fields.get(field) is not None
    }

    if check.status_code == 404:
        data["name"] = name
        response = session.post(
            namespace,
            data=data,
            params={"output_mode": "json"},
            timeout=30,
        )
        action = "created"
    else:
        response = session.post(
            item_url,
            data=data,
            params={"output_mode": "json"},
            timeout=30,
        )
        action = "restored"

    response.raise_for_status()
    return action


def verify_snapshot(
    session: requests.Session,
    namespace: str,
    snapshot: dict,
    disable_extra: bool,
) -> tuple[list[dict], list[str]]:
    live = get_all_managed(session, namespace)
    expected_names = {str(item["name"]) for item in snapshot["searches"]}
    findings: list[str] = []
    rows: list[dict] = []

    for item in snapshot["searches"]:
        name = str(item["name"])
        entry = live.get(name)
        if entry is None:
            findings.append(f"{name}: missing after rollback")
            rows.append({"name": name, "status": "ERROR"})
            continue

        content = entry.get("content", {})
        mismatches = []
        for field in RESTORE_FIELDS:
            expected = item["fields"].get(field)
            if expected is None:
                continue
            actual = content.get(field)
            if normalized_field(field, actual) != normalized_field(field, expected):
                mismatches.append(field)

        if mismatches:
            findings.append(
                f"{name}: restored fields do not match snapshot: {', '.join(mismatches)}"
            )
            rows.append({"name": name, "status": "ERROR"})
        else:
            rows.append({"name": name, "status": "RESTORED"})

    extra_names = sorted(set(live) - expected_names)
    for name in extra_names:
        disabled = boolish(live[name].get("content", {}).get("disabled"))
        if disable_extra and not disabled:
            findings.append(f"{name}: extra managed search is still enabled")
            rows.append({"name": name, "status": "ERROR"})
        else:
            rows.append(
                {
                    "name": name,
                    "status": "DISABLED_EXTRA" if disabled else "EXTRA",
                }
            )

    return rows, findings


def escape_cell(value: str) -> str:
    return value.replace("|", "&#124;")


def write_report(
    report_dir: Path,
    snapshot: dict,
    rows: list[dict],
    findings: list[str],
    dry_run: bool,
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    payload = {
        "generated_at": generated_at,
        "dry_run": dry_run,
        "snapshot_created_at": snapshot.get("created_at"),
        "snapshot_source_run_id": snapshot.get("source_run_id"),
        "restored_repository_commit": snapshot.get("repository_commit"),
        "searches": rows,
        "findings": findings,
        "status": "ERROR" if findings else "SUCCESS",
    }
    (report_dir / "rollback-report.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Splunk Detection Rollback",
        "",
        f"Status: **{payload['status']}**",
        f"Snapshot source run: {payload['snapshot_source_run_id']}",
        f"Restored deployed commit: {payload['restored_repository_commit']}",
        f"Snapshot created: {payload['snapshot_created_at']}",
        "",
        "| Saved search | Result |",
        "|---|---|",
    ]
    for row in rows:
        lines.append(f"| {escape_cell(row['name'])} | {row['status']} |")

    if findings:
        lines.extend(["", "## Findings", ""])
        lines.extend(f"- {finding}" for finding in findings)

    (report_dir / "rollback-report.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore DaC-managed Splunk saved searches from a snapshot"
    )
    parser.add_argument("--snapshot", required=True, help="Snapshot JSON to restore")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Actually restore the snapshot (default: preview)",
    )
    parser.add_argument(
        "--disable-extra",
        action="store_true",
        help="Disable managed searches not present in the snapshot",
    )
    parser.add_argument(
        "--report-dir",
        default="reports/rollback",
        help="Rollback report output directory",
    )
    args = parser.parse_args()

    snapshot = load_snapshot(Path(args.snapshot))
    expected = snapshot["searches"]
    print(
        f"Snapshot contains {len(expected)} managed searches from "
        f"run {snapshot.get('source_run_id')} / commit "
        f"{snapshot.get('repository_commit')}"
    )

    if not args.live:
        for item in expected:
            print(f"DRY RUN: would restore {item['name']}")
        if args.disable_extra:
            print("DRY RUN: would disable DaC-managed searches absent from snapshot")
        return 0

    base = check_target(os.getenv("SPLUNK_MANAGEMENT_URL", ""))
    token = os.getenv("SPLUNK_TOKEN", "")
    app = os.getenv("SPLUNK_APP", snapshot.get("splunk_app", "search"))
    if not token:
        raise SystemExit("SPLUNK_TOKEN is required")

    ca_bundle = os.getenv("SPLUNK_CA_BUNDLE")
    verify: bool | str = (
        ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    )
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab rollback")

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify

    namespace = f"{base}/servicesNS/nobody/{quote(app, safe='')}/saved/searches"

    for item in expected:
        action = restore_one(session, namespace, str(item["name"]), item["fields"])
        print(f"{action.upper()}: {item['name']}")

    if args.disable_extra:
        expected_names = {str(item["name"]) for item in expected}
        live = get_all_managed(session, namespace)
        for name in sorted(set(live) - expected_names):
            item_url = f"{namespace}/{quote(name, safe='')}"
            response = session.post(
                item_url,
                data={"disabled": "1"},
                params={"output_mode": "json"},
                timeout=20,
            )
            response.raise_for_status()
            print(f"DISABLED EXTRA: {name}")

    rows, findings = verify_snapshot(
        session,
        namespace,
        snapshot,
        args.disable_extra,
    )
    session.close()

    write_report(
        Path(args.report_dir),
        snapshot,
        rows,
        findings,
        dry_run=False,
    )

    if findings:
        for finding in findings:
            print(f"ERROR: {finding}")
        print(f"\nRollback verification failed with {len(findings)} finding(s)")
        return 1

    print(
        f"\nRollback verified: {len(expected)} searches restored from "
        f"run {snapshot.get('source_run_id')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
