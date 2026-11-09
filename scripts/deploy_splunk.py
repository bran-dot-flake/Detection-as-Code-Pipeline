"""Idempotent Splunk Enterprise saved-search deployment (OFF unless --live)."""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import quote, urlsplit
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "splunk"


def check_target(url):
    if not url or urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
        raise SystemExit("SPLUNK_MANAGEMENT_URL must be an https:// Splunk management URL (e.g. https://splunk.local:8089)")
    return url.rstrip("/")


def env_bool(name, default=True):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def deploy(session, base_url, app, index, name, query):
    namespace = f"{base_url}/servicesNS/nobody/{quote(app, safe='')}/saved/searches"
    item_url = f"{namespace}/{quote(name, safe='')}"
    check = session.get(item_url, params={"output_mode": "json"}, timeout=20)
    if check.status_code not in (200, 404):
        check.raise_for_status()
    # Scope every deployed detection to the configured Splunk index.
    compiled = query.strip()
    if compiled.lower().startswith("search "):
        compiled = compiled[7:].strip()
    if compiled.startswith("|"):
        raise RuntimeError(f"Unexpected compiled SPL form for {name}: {compiled}")
    query = f'search index="{index}" {compiled}'
    data = {
        "search": query,
        "is_scheduled": "1",
        "cron_schedule": "*/5 * * * *",
        "dispatch.earliest_time": "-5m@m",
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "true",
        "description": "Managed by the Detection-as-Code-Pipeline repository.",
        "disabled": "0",
    }
    if check.status_code == 404:
        data["name"] = name
        response = session.post(namespace, data=data, params={"output_mode": "json"}, timeout=20)
        action = "created"
    else:
        response = session.post(item_url, data=data, params={"output_mode": "json"}, timeout=20)
        action = "updated"
    response.raise_for_status()
    return action


def main():
    parser = argparse.ArgumentParser(description="Preview or deploy Splunk alerts")
    parser.add_argument("--live", action="store_true", help="Actually create/update alerts (default: dry-run)")
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
    if args.live and not token:
        raise SystemExit("Missing SPLUNK_TOKEN")
    if args.live:
        base = check_target(base)
    ca_bundle = os.environ.get("SPLUNK_CA_BUNDLE")
    verify = ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab deployment")

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify
    for entry in entries:
        name = "DaC - " + entry["title"]
        query = (OUT / entry["filename"]).read_text(encoding="utf-8").strip()
        if not args.live:
            print(f"DRY RUN: would deploy {name} ({entry['filename']})")
        else:
            result = deploy(session, base, app, index, name, query)
            print(f"{result.upper()}: {name}")
    session.close()


if __name__ == "__main__":
    main()
