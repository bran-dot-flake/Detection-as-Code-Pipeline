"""Compile each Sigma rule to SPL. Run only after backtests pass."""
from pathlib import Path
import json
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "sigma"
OUT = ROOT / "dist" / "splunk"


def main() -> int:
    rules = sorted([*RULES.rglob("*.yml"), *RULES.rglob("*.yaml")])
    if not rules:
        raise SystemExit("No Sigma YAML rules found: refusing empty build")
    OUT.mkdir(parents=True, exist_ok=True)
    entries = []
    seen_ids = set()
    for rule in rules:
        data = yaml.safe_load(rule.read_text(encoding="utf-8"))
        rule_id, title = str(data["id"]), str(data["title"])
        if rule_id in seen_ids:
            raise SystemExit(f"Duplicate rule ID: {rule_id}")
        seen_ids.add(rule_id)
        command = ["sigma", "convert", "-t", "splunk", "-p", "sysmon", str(rule)]
        run = subprocess.run(command, capture_output=True, text=True, check=False)
        if run.returncode:
            print(run.stderr, file=sys.stderr)
            raise SystemExit(f"Failed to convert {rule}")
        query = run.stdout.strip()
        if not query:
            raise SystemExit(f"Conversion produced no query: {rule}")
        filename = f"{rule_id}.spl"
        (OUT / filename).write_text(query + "\n", encoding="utf-8")
        entries.append({"id": rule_id, "title": title, "filename": filename,
                        "source": str(rule.relative_to(ROOT))})
        print(f"Converted {rule.relative_to(ROOT)} -> {filename}")
    (OUT / "manifest.json").write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    print(f"Built {len(entries)} SPL detection(s) in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
