"""Report lifecycle health for Detection-as-Code managed Splunk searches."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "sigma"


def env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def boolish(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_search(search: str) -> str:
    return " ".join(search.split())


def query_sha256(search: str) -> str:
    return hashlib.sha256(normalize_search(search).encode("utf-8")).hexdigest()


def parse_metadata(description: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for part in description.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def load_expected_rules() -> list[dict]:
    rules: list[dict] = []
    paths = sorted([*RULES.rglob("*.yml"), *RULES.rglob("*.yaml")])
    for path in paths:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(
            {
                "id": str(data["id"]),
                "title": str(data["title"]),
                "name": "DaC - " + str(data["title"]),
                "source": str(path.relative_to(ROOT)),
            }
        )
    if not rules:
        raise SystemExit("No Sigma rules found")
    return rules


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def newest_history_entry(entries: list[dict]) -> dict | None:
    if not entries:
        return None

    def key(entry: dict):
        parsed = parse_time(entry.get("published")) or parse_time(entry.get("updated"))
        return parsed or datetime.min.replace(tzinfo=timezone.utc)

    return max(entries, key=key)


def job_state(entry: dict | None) -> str:
    if not entry:
        return "NO_HISTORY"
    content = entry.get("content", {})
    state = (
        content.get("dispatchState")
        or content.get("dispatch_state")
        or content.get("state")
    )
    if state:
        return str(state).upper()
    if boolish(content.get("isDone")):
        return "DONE"
    return "UNKNOWN"


def history_time(entry: dict | None) -> str:
    if not entry:
        return "-"
    return entry.get("published") or entry.get("updated") or "-"


def history_result_count(entry: dict | None) -> str:
    if not entry:
        return "-"
    content = entry.get("content", {})
    value = (
        content.get("resultCount")
        if "resultCount" in content
        else content.get("result_count")
    )
    return "-" if value is None else str(value)


def get_saved_search(
    session: requests.Session,
    base: str,
    app: str,
    name: str,
) -> tuple[dict | None, str]:
    item = (
        f"{base}/servicesNS/nobody/{quote(app, safe='')}"
        f"/saved/searches/{quote(name, safe='')}"
    )
    response = session.get(
        item,
        params={"output_mode": "json", "add_orphan_field": "true"},
        timeout=20,
    )
    if response.status_code == 404:
        return None, item
    response.raise_for_status()
    entries = response.json().get("entry", [])
    return (entries[0] if entries else None), item


def get_history(
    session: requests.Session,
    item_url: str,
) -> tuple[list[dict], str | None]:
    response = session.get(
        item_url + "/history",
        params={"output_mode": "json", "count": 10},
        timeout=20,
    )
    if response.status_code in (403, 404):
        return [], f"history endpoint returned {response.status_code}"
    response.raise_for_status()
    return response.json().get("entry", []), None


def get_all_managed(
    session: requests.Session,
    base: str,
    app: str,
) -> dict[str, dict]:
    namespace = (
        f"{base}/servicesNS/nobody/{quote(app, safe='')}/saved/searches"
    )
    response = session.get(
        namespace,
        params={"output_mode": "json", "count": 0},
        timeout=30,
    )
    response.raise_for_status()
    return {
        str(entry["name"]): entry
        for entry in response.json().get("entry", [])
        if str(entry.get("name", "")).startswith("DaC - ")
    }


def assess_rule(
    session: requests.Session,
    base: str,
    app: str,
    expected_commit: str | None,
    rule: dict,
) -> dict:
    errors: list[str] = []
    warnings: list[str] = []

    entry, item_url = get_saved_search(session, base, app, rule["name"])
    if entry is None:
        return {
            **rule,
            "status": "ERROR",
            "errors": ["saved search is missing"],
            "warnings": [],
            "scheduled": False,
            "enabled": False,
            "cron": "-",
            "next_run": "-",
            "last_run": "-",
            "last_state": "MISSING",
            "result_count": "-",
            "deployed_commit": "-",
            "query_drift": "unknown",
        }

    content = entry.get("content", {})
    disabled = boolish(content.get("disabled"))
    scheduled = boolish(content.get("is_scheduled"))

    if disabled:
        errors.append("saved search is disabled")
    if not scheduled:
        errors.append("saved search is not scheduled")

    metadata = parse_metadata(str(content.get("description", "")))
    deployed_rule_id = metadata.get("rule_id")
    deployed_commit = metadata.get("commit", "-")
    deployed_hash = metadata.get("query_sha256")

    if deployed_rule_id != rule["id"]:
        errors.append("managed rule_id metadata does not match repository rule")

    if (
        expected_commit
        and expected_commit != "local"
        and deployed_commit != expected_commit
    ):
        errors.append(
            f"deployed commit is {deployed_commit}, expected {expected_commit}"
        )

    deployed_query = str(content.get("search", ""))
    actual_hash = query_sha256(deployed_query) if deployed_query else None
    query_drift = "no"
    if not deployed_hash:
        errors.append("query_sha256 deployment metadata is missing")
        query_drift = "unknown"
    elif actual_hash != deployed_hash:
        errors.append("deployed SPL hash no longer matches managed metadata")
        query_drift = "YES"

    history, history_warning = get_history(session, item_url)
    if history_warning:
        warnings.append(history_warning)

    latest = newest_history_entry(history)
    state = job_state(latest)
    failed_states = {"FAILED", "FAIL", "ERROR", "CANCELED", "CANCELLED", "QUIT"}
    in_progress_states = {
        "QUEUED",
        "PARSING",
        "RUNNING",
        "FINALIZING",
        "PAUSED",
    }

    if state in failed_states:
        errors.append(f"latest scheduler job state is {state}")
    elif state == "NO_HISTORY":
        warnings.append("no saved-search execution history is available yet")
    elif state in in_progress_states:
        warnings.append(f"latest scheduler job is still {state}")
    elif state not in {"DONE", "UNKNOWN"}:
        warnings.append(f"unrecognized scheduler job state: {state}")

    status = "ERROR" if errors else "WARN" if warnings else "HEALTHY"
    return {
        **rule,
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "scheduled": scheduled,
        "enabled": not disabled,
        "cron": str(content.get("cron_schedule", "-")),
        "next_run": str(content.get("next_scheduled_time", "-")),
        "last_run": history_time(latest),
        "last_state": state,
        "result_count": history_result_count(latest),
        "deployed_commit": deployed_commit,
        "query_drift": query_drift,
    }


def markdown_report(generated_at: str, commit: str, results: list[dict]) -> str:
    errors = sum(r["status"] == "ERROR" for r in results)
    warnings = sum(r["status"] == "WARN" for r in results)
    healthy = sum(r["status"] == "HEALTHY" for r in results)

    lines = [
        "# Splunk Detection Health",
        "",
        f"Generated: {generated_at}",
        f"Repository commit: {commit}",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Managed detections | {len(results)} |",
        f"| Healthy | {healthy} |",
        f"| Warnings | {warnings} |",
        f"| Errors | {errors} |",
        "",
        "| Detection | Status | Enabled | Scheduled | Cron | Last job | Query drift |",
        "|---|---|:---:|:---:|---|---|:---:|",
    ]

    for item in results:
        lines.append(
            "| "
            + " | ".join(
                [
                    item["name"].replace("|", "\\|"),
                    item["status"],
                    "yes" if item["enabled"] else "no",
                    "yes" if item["scheduled"] else "no",
                    item["cron"].replace("|", "\\|"),
                    item["last_state"],
                    item["query_drift"],
                ]
            )
            + " |"
        )

    detail_items = [item for item in results if item["errors"] or item["warnings"]]
    if detail_items:
        lines.extend(["", "## Findings", ""])
        for item in detail_items:
            lines.append(f"### {item['name']}")
            lines.append("")
            for message in item["errors"]:
                lines.append(f"- ERROR: {message}")
            for message in item["warnings"]:
                lines.append(f"- WARN: {message}")
            lines.append("")

    lines.extend(
        [
            "",
            "## Scheduler detail",
            "",
            "| Detection | Next run | Last run | Last state | Last result count | Deployed commit |",
            "|---|---|---|---|---:|---|",
        ]
    )
    for item in results:
        lines.append(
            "| "
            + " | ".join(
                [
                    item["name"].replace("|", "\\|"),
                    item["next_run"],
                    item["last_run"],
                    item["last_state"],
                    item["result_count"],
                    item["deployed_commit"],
                ]
            )
            + " |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check health of DaC-managed Splunk detections"
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory for JSON and Markdown reports",
    )
    args = parser.parse_args()

    base = os.getenv("SPLUNK_MANAGEMENT_URL", "").rstrip("/")
    token = os.getenv("SPLUNK_TOKEN", "")
    app = os.getenv("SPLUNK_APP", "search")
    expected_commit = os.getenv("GITHUB_SHA")

    if (
        not base
        or urlsplit(base).scheme != "https"
        or not urlsplit(base).hostname
    ):
        raise SystemExit("SPLUNK_MANAGEMENT_URL must be an https:// management URL")
    if not token:
        raise SystemExit("SPLUNK_TOKEN is required")

    ca_bundle = os.getenv("SPLUNK_CA_BUNDLE")
    verify: bool | str = (
        ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    )
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab health check")

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify

    server = session.get(
        f"{base}/services/server/info",
        params={"output_mode": "json"},
        timeout=20,
    )
    server.raise_for_status()

    expected_rules = load_expected_rules()
    results = [
        assess_rule(session, base, app, expected_commit, rule)
        for rule in expected_rules
    ]

    expected_names = {rule["name"] for rule in expected_rules}
    live_managed = get_all_managed(session, base, app)
    for name in sorted(set(live_managed) - expected_names):
        content = live_managed[name].get("content", {})
        disabled = boolish(content.get("disabled"))
        if disabled:
            continue
        results.append(
            {
                "id": "-",
                "title": name.removeprefix("DaC - "),
                "name": name,
                "source": "splunk-only",
                "status": "ERROR",
                "errors": [
                    "managed saved search is enabled in Splunk but absent from Git"
                ],
                "warnings": [],
                "scheduled": boolish(content.get("is_scheduled")),
                "enabled": True,
                "cron": str(content.get("cron_schedule", "-")),
                "next_run": str(content.get("next_scheduled_time", "-")),
                "last_run": "-",
                "last_state": "ORPHANED",
                "result_count": "-",
                "deployed_commit": parse_metadata(
                    str(content.get("description", ""))
                ).get("commit", "-"),
                "query_drift": "unknown",
            }
        )
    session.close()

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    commit = expected_commit or "local"

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": generated_at,
        "repository_commit": commit,
        "summary": {
            "managed": len(results),
            "healthy": sum(r["status"] == "HEALTHY" for r in results),
            "warnings": sum(r["status"] == "WARN" for r in results),
            "errors": sum(r["status"] == "ERROR" for r in results),
        },
        "detections": results,
    }

    (report_dir / "splunk-health.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    (report_dir / "splunk-health.md").write_text(
        markdown_report(generated_at, commit, results),
        encoding="utf-8",
    )

    for item in results:
        print(
            f"{item['status']}: {item['name']} "
            f"(enabled={item['enabled']}, "
            f"scheduled={item['scheduled']}, "
            f"last={item['last_state']}, "
            f"drift={item['query_drift']})"
        )

    error_count = payload["summary"]["errors"]
    warning_count = payload["summary"]["warnings"]
    print(
        f"\nDetection health: "
        f"{payload['summary']['healthy']} healthy, "
        f"{warning_count} warning, "
        f"{error_count} error"
    )
    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
