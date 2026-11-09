"""End-to-end Splunk integration test for compiled Sigma detections.

Loads the repository's NDJSON fixtures into a lab Splunk index through the
management REST API, then executes the generated SPL and verifies the total
match count for each rule.

Required environment variables:
  SPLUNK_MANAGEMENT_URL  e.g. https://192.168.89.191:8089
  SPLUNK_TOKEN           bearer token (never commit this)

Optional:
  SPLUNK_INDEX           default: sysmon
  SPLUNK_VERIFY_TLS      default: true; set false only for a lab/self-signed cert
  SPLUNK_CA_BUNDLE       path to a trusted CA bundle
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "sample-logs"
EXPECTATIONS = ROOT / "ci" / "expectations.yml"
BUILD = ROOT / "dist" / "splunk"

SOURCE = "WinEventLog:Microsoft-Windows-Sysmon/Operational"
SOURCETYPE = "_json"
HOST = "dac-integration-lab"


def env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def make_session(token: str, verify: bool | str) -> requests.Session:
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    session.verify = verify
    return session


def verify_server(session: requests.Session, base: str) -> None:
    response = session.get(
        f"{base}/services/server/info",
        params={"output_mode": "json"},
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    entries = payload.get("entry", [])
    version = entries[0].get("content", {}).get("version", "unknown") if entries else "unknown"
    print(f"Connected to Splunk {version} at {base}")


def corpus_records(run_id: str) -> list[dict]:
    records: list[dict] = []
    for path in sorted(CORPUS.rglob("*.ndjson")):
        rel = str(path.relative_to(CORPUS))
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            # The Splunk Windows pySigma processing pipeline maps Sigma EventID
            # to Splunk's EventCode field. Preserve EventID for provenance too.
            event["EventCode"] = event.get("EventID")
            event["DaCTestRunId"] = run_id
            event["DaCCorpus"] = rel
            event["DaCLine"] = line_number
            records.append(event)
    if not records:
        raise SystemExit("No NDJSON test events found")
    return records


def ingest(
    session: requests.Session,
    base: str,
    index: str,
    records: list[dict],
) -> None:
    endpoint = f"{base}/services/receivers/simple"
    params = {
        "index": index,
        "source": SOURCE,
        "sourcetype": SOURCETYPE,
        "host": HOST,
    }
    for number, event in enumerate(records, 1):
        response = session.post(
            endpoint,
            params=params,
            data=json.dumps(event, separators=(",", ":")),
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        response.raise_for_status()
        print(f"Indexed test event {number}/{len(records)}", end="\r")
    print()


def parse_export_count(body: str) -> int:
    """Parse a single-row '| stats count as count' v2 export response."""
    lines = [line for line in body.splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = obj.get("result")
        if isinstance(result, dict) and "count" in result:
            return int(result["count"])
        results = obj.get("results")
        if isinstance(results, list) and results and "count" in results[0]:
            return int(results[0]["count"])
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            result = obj.get("result", obj)
            if isinstance(result, dict) and "count" in result:
                return int(result["count"])
    except json.JSONDecodeError:
        pass
    raise RuntimeError(f"Could not parse count from Splunk response: {body[:500]!r}")


def run_count_search(
    session: requests.Session,
    base: str,
    index: str,
    run_id: str,
    spl: str,
) -> int:
    compiled = spl.strip()
    if compiled.lower().startswith("search "):
        compiled = compiled[7:].strip()
    if compiled.startswith("|"):
        raise RuntimeError(f"Unexpected compiled SPL form: {compiled}")

    # Find only this run by raw JSON first, then explicitly extract JSON fields.
    # This avoids depending on automatic search-time field extraction being
    # available/configured for the fresh lab sourcetype.
    raw_marker = f'DaCTestRunId*{run_id}'
    # pySigma's Splunk backend can append pipeline commands such as
    # "| table ..." when the Sigma rule defines a fields: section. Compose
    # the generated SPL directly after "| search" instead of wrapping the
    # whole generated string in parentheses.
    search = (
        f'search index="{index}" _raw="*{raw_marker}*" '
        "| spath "
        f"| search {compiled} "
        "| stats count as count"
    )
    response = session.post(
        f"{base}/services/search/v2/jobs/export",
        data={
            "search": search,
            "output_mode": "json",
            # Use index time so the historical UtcTime values in fixtures do not
            # exclude newly ingested events from this integration test.
            "earliest_time": "0",
            "latest_time": "now",
            "index_earliest": "-10m",
            "index_latest": "now",
        },
        timeout=60,
    )
    response.raise_for_status()
    if not response.text.strip():
        raise RuntimeError(
            "Splunk returned an empty export response for generated search:\n"
            + search
        )
    return parse_export_count(response.text)


def wait_until_indexed(
    session: requests.Session,
    base: str,
    index: str,
    run_id: str,
    expected: int,
) -> None:
    raw_marker = f'DaCTestRunId*{run_id}'
    search = (
        f'search index="{index}" _raw="*{raw_marker}*" '
        "| stats count as count"
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        response = session.post(
            f"{base}/services/search/v2/jobs/export",
            data={
                "search": search,
                "output_mode": "json",
                "index_earliest": "-10m",
                "index_latest": "now",
            },
            timeout=60,
        )
        response.raise_for_status()
        count = parse_export_count(response.text)
        if count >= expected:
            print(f"Splunk indexed {count}/{expected} test events")
            return
        time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {expected} test events to be indexed")


def expected_rule_totals() -> dict[str, int]:
    data = yaml.safe_load(EXPECTATIONS.read_text(encoding="utf-8"))
    totals: dict[str, int] = {}
    for item in data["expectations"]:
        rule_id = str(item["rule"])
        totals[rule_id] = totals.get(rule_id, 0) + int(item["exactly"])
    return totals


def manifest_entries() -> list[dict]:
    manifest = BUILD / "manifest.json"
    if not manifest.is_file():
        raise SystemExit(
            "Missing dist/splunk/manifest.json. Run: python scripts/build_splunk.py"
        )
    return json.loads(manifest.read_text(encoding="utf-8"))


def main() -> int:
    base = os.getenv("SPLUNK_MANAGEMENT_URL", "").rstrip("/")
    token = os.getenv("SPLUNK_TOKEN", "")
    index = os.getenv("SPLUNK_INDEX", "sysmon")
    if not base.startswith("https://"):
        raise SystemExit("SPLUNK_MANAGEMENT_URL must start with https://")
    if not token:
        raise SystemExit("SPLUNK_TOKEN is required")

    ca_bundle = os.getenv("SPLUNK_CA_BUNDLE")
    verify: bool | str = ca_bundle if ca_bundle else env_bool("SPLUNK_VERIFY_TLS", True)
    if verify is False:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        print("WARNING: TLS verification is disabled for this lab run")

    session = make_session(token, verify)
    verify_server(session, base)

    run_id = f"dac-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    records = corpus_records(run_id)
    print(f"Integration run: {run_id}")
    ingest(session, base, index, records)
    wait_until_indexed(session, base, index, run_id, len(records))

    totals = expected_rule_totals()
    failures = 0
    for entry in manifest_entries():
        rule_id = str(entry["id"])
        title = entry["title"]
        expected = totals.get(rule_id)
        if expected is None:
            print(f"FAIL {title}: no expectation total found")
            failures += 1
            continue
        spl = (BUILD / entry["filename"]).read_text(encoding="utf-8")
        actual = run_count_search(session, base, index, run_id, spl)
        outcome = "PASS" if actual == expected else "FAIL"
        print(f"{outcome} {title}: expected {expected}, Splunk returned {actual}")
        failures += int(actual != expected)

    session.close()
    if failures:
        print(f"\nSplunk integration test failed: {failures} detection(s) mismatched")
        return 1

    print("\nSplunk integration test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
