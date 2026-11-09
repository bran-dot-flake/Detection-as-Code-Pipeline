"""Create a pre-deployment snapshot of DaC-managed Splunk saved searches."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

MANAGED_PREFIX = "DaC - "
OWNED_FIELDS = [
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


def parse_metadata(description: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for part in description.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        metadata[key.strip()] = value.strip()
    return metadata


def check_target(url: str) -> str:
    if not url or urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
        raise SystemExit("SPLUNK_MANAGEMENT_URL must be an https:// management URL")
    return url.rstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Snapshot DaC-managed Splunk saved searches before deployment"
    )
    parser.add_argument(
        "--output",
        default="rollback/splunk-backup.json",
        help="Snapshot output path",
    )
    args = parser.parse_args()

    base = check_target(os.getenv("SPLUNK_MANAGEMENT_URL", ""))
    token = os.getenv("SPLUNK_TOKEN", "")
    app = os.getenv("SPLUNK_APP", "search")
    if not token:
        raise SystemExit("SPLUNK_TOKEN is required")

    ca_bundle = os.getenv("SPLUNK_CA_BUNDLE")
    verify: bool | str = (
        ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    )
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab snapshot")

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify

    namespace = f"{base}/servicesNS/nobody/{quote(app, safe='')}/saved/searches"
    response = session.get(
        namespace,
        params={
            "output_mode": "json",
            "count": 0,
            "add_orphan_field": "true",
        },
        timeout=30,
    )
    response.raise_for_status()
    entries = response.json().get("entry", [])
    session.close()

    managed = [entry for entry in entries if str(entry.get("name", "")).startswith(MANAGED_PREFIX)]
    if not managed:
        raise SystemExit("No DaC-managed saved searches were found to snapshot")

    searches = []
    commits: set[str] = set()
    for entry in sorted(managed, key=lambda item: str(item.get("name", ""))):
        content = entry.get("content", {})
        fields = {field: content.get(field) for field in OWNED_FIELDS}
        description = str(fields.get("description") or "")
        metadata = parse_metadata(description)
        deployed_commit = metadata.get("commit")
        if deployed_commit:
            commits.add(deployed_commit)

        searches.append(
            {
                "name": str(entry["name"]),
                "fields": fields,
                "metadata": {
                    "rule_id": metadata.get("rule_id"),
                    "commit": deployed_commit,
                    "query_sha256": metadata.get("query_sha256"),
                },
            }
        )

    repository_commit = next(iter(commits)) if len(commits) == 1 else "mixed"
    payload = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "source_workflow_sha": os.getenv("GITHUB_SHA", "local"),
        "repository_commit": repository_commit,
        "splunk_app": app,
        "managed_prefix": MANAGED_PREFIX,
        "owned_fields": OWNED_FIELDS,
        "searches": searches,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(
        f"Snapshot saved {len(searches)} managed searches to {output} "
        f"(deployed commit: {repository_commit})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
