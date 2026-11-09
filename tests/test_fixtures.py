"""Fast corpus hygiene tests; RSigma performs the actual detection evaluation."""
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "sample-logs"


def test_corpus_is_well_formed_process_creation_data():
    paths = list(CORPUS.rglob("*.ndjson"))
    assert paths, "No corpus files found"
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines, f"Empty corpus: {path}"
        for lineno, line in enumerate(lines, 1):
            record = json.loads(line)
            assert isinstance(record, dict), (path, lineno)
            assert record.get("EventID") == 1, (path, lineno, "expected Sysmon Event ID 1")
            assert record.get("Image"), (path, lineno, "missing Image")
            assert record.get("ParentImage"), (path, lineno, "missing ParentImage")


def test_expectations_cover_every_corpus_file():
    data = yaml.safe_load((ROOT / "ci" / "expectations.yml").read_text(encoding="utf-8"))
    covered = {entry["corpus"] for entry in data["expectations"]}
    present = {str(p.relative_to(CORPUS)) for p in CORPUS.rglob("*.ndjson")}
    assert present == covered, f"Missing expectations for: {present - covered}; stale expectations: {covered - present}"


def test_sigma_rule_ids_are_unique():
    ids = []
    for path in (ROOT / "rules" / "sigma").rglob("*.yml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data.get("id"), f"Missing rule id: {path}"
        ids.append(data["id"])
    assert len(ids) == len(set(ids)), "Duplicate Sigma rule IDs found"
