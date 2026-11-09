"""Fast fixture hygiene tests; RSigma performs the actual detection evaluation."""
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "sample-logs"


def test_corpus_is_well_formed_and_has_expected_fields():
    paths = list(CORPUS.rglob("*.ndjson"))
    assert paths, "No corpus files found"
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines, f"Empty corpus: {path}"
        for lineno, line in enumerate(lines, 1):
            record = json.loads(line)
            assert isinstance(record, dict), (path, lineno)
            assert all(key in record for key in ("EventID", "Image", "CommandLine")), (path, lineno)
            assert record["EventID"] == 1, (path, lineno)


def test_expectations_cover_all_demo_corpora():
    data = yaml.safe_load((ROOT / "ci" / "expectations.yml").read_text(encoding="utf-8"))
    covered = {entry["corpus"] for entry in data["expectations"]}
    present = {str(p.relative_to(CORPUS)) for p in CORPUS.rglob("*.ndjson")}
    assert present == covered, f"Missing expectations for: {present - covered}"
