"""Idempotent Splunk saved-search deployment with desired-state reconciliation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "splunk"
MANAGED_PREFIX = "DaC - "


def check_target(url):
    if not url or urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
        raise SystemExit(
            "SPLUNK_MANAGEMENT_URL must be an https:// Splunk management URL "
            "(e.g. https://splunk.local:8089)"
        )
    return url.rstrip("/")


def env_bool(name, default=True):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def normalize_search(search):
    return " ".join(search.split())


def query_sha256(search):
    return hashlib.sha256(normalize_search(search).encode("utf-8")).hexdigest()


def managed_description(rule_id, commit_sha, query):
    return (
        "Managed by Detection-as-Code-Pipeline; "
        f"rule_id={rule_id}; "
        f"commit={commit_sha}; "
        f"query_sha256={query_sha256(query)}"
    )


def namespace_url(base_url, app):
    return f"{base_url}/servicesNS/nobody/{quote(app, safe='')}/saved/searches"


def list_managed_searches(session, base_url, app):
    namespace = namespace_url(base_url, app)
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


def deploy(session, base_url, app, index, rule_id, commit_sha, name, query):
    namespace = namespace_url(base_url, app)
    item_url = f"{namespace}/{quote(name, safe='')}"
    check = session.get(item_url, params={"output_mode": "json"}, timeout=20)
    if check.status_code not in (200, 404):
        check.raise_for_status()

    compiled = query.strip()
    if compiled.lower().startswith("search "):
        compiled = compiled[7:].strip()
    if compiled.startswith("|"):
        raise RuntimeError(f"Unexpected compiled SPL form for {name}: {compiled}")

    deployed_query = f'search index="{index}" {compiled}'
    data = {
        "search": deployed_query,
        "is_scheduled": "1",
        "cron_schedule": "*/5 * * * *",
        "dispatch.earliest_time": "-5m@m",
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "true",
        "description": managed_description(rule_id, commit_sha, deployed_query),
        "disabled": "0",
    }

    if check.status_code == 404:
        data["name"] = name
        response = session.post(
            namespace,
            data=data,
            params={"output_mode": "json"},
            timeout=20,
        )
        action = "created"
    else:
        response = session.post(
            item_url,
            data=data,
            params={"output_mode": "json"},
            timeout=20,
        )
        action = "updated"

    response.raise_for_status()
    return action


def reconcile_removed_searches(session, base_url, app, desired_names):
    """Disable managed Splunk searches that no longer exist in Git."""
    managed = list_managed_searches(session, base_url, app)
    stale = sorted(set(managed) - set(desired_names))
    namespace = namespace_url(base_url, app)

    for name in stale:
        content = managed[name].get("content", {})
        disabled = str(content.get("disabled", "0")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if disabled:
            print(f"RETIRED: {name} (already disabled)")
            continue

        item_url = f"{namespace}/{quote(name, safe='')}"
        response = session.post(
            item_url,
            data={"disabled": "1"},
            params={"output_mode": "json"},
            timeout=20,
        )
        response.raise_for_status()
        print(f"RETIRED: {name} (disabled because it is absent from Git)")

    return stale


def main():
    parser = argparse.ArgumentParser(description="Preview or deploy Splunk alerts")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Actually create/update alerts (default: dry-run)",
    )
    args = parser.parse_args()

    manifest = OUT / "manifest.json"
    if not manifest.is_file():
        raise SystemExit("Build first: python scripts/build_splunk.py")

    entries = json.loads(manifest.read_text(encoding="utf-8"))
    if not entries:
        raise SystemExit("Empty build manifest")

    base = os.environ.get("SPLUNK_MANAGEMENT_URL", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    app = os.environ.get("SPLUNK_APP", "search")
    index = os.environ.get("SPLUNK_INDEX", "sysmon")
    commit_sha = os.environ.get("GITHUB_SHA", "local")

    if args.live and not token:
        raise SystemExit("Missing SPLUNK_TOKEN")
    if args.live:
        base = check_target(base)

    ca_bundle = os.environ.get("SPLUNK_CA_BUNDLE")
    verify = ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab deployment")

    desired_names = {"DaC - " + entry["title"] for entry in entries}
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify

    for entry in entries:
        name = "DaC - " + entry["title"]
        query = (OUT / entry["filename"]).read_text(encoding="utf-8").strip()
        if not args.live:
            print(f"DRY RUN: would deploy {name} ({entry['filename']})")
        else:
            result = deploy(
                session,
                base,
                app,
                index,
                str(entry["id"]),
                commit_sha,
                name,
                query,
            )
            print(f"{result.upper()}: {name}")

    if args.live:
        reconcile_removed_searches(session, base, app, desired_names)
    else:
        print("DRY RUN: live reconciliation of removed detections is skipped")

    session.close()


if __name__ == "__main__":
    main()
