"""Fast corpus/expectation hygiene tests; RSigma performs detection evaluation."""
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "sample-logs"
RULES = ROOT / "rules" / "sigma"


def _corpus_files():
    return sorted(CORPUS.rglob("*.ndjson"))


def _rule_files():
    return sorted([*RULES.rglob("*.yml"), *RULES.rglob("*.yaml")])


def test_corpus_is_well_formed_sysmon_data():
    paths = _corpus_files()
    assert paths, "No corpus files found"
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines, f"Empty corpus: {path}"
        for lineno, line in enumerate(lines, 1):
            record = json.loads(line)
            assert isinstance(record, dict), (path, lineno)
            event_id = record.get("EventID")
            assert event_id in (1, 3, 22), (
                path,
                lineno,
                f"unsupported demo EventID {event_id}",
            )
            assert record.get("Image"), (path, lineno, "missing Image")

            if event_id == 3:
                assert record.get("DestinationIp"), (
                    path,
                    lineno,
                    "missing DestinationIp",
                )
                assert "DestinationPort" in record, (
                    path,
                    lineno,
                    "missing DestinationPort",
                )
            elif event_id == 22:
                assert record.get("QueryName"), (path, lineno, "missing QueryName")


def test_sigma_rule_ids_are_unique_and_present():
    ids = []
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data.get("id"), f"Missing rule id: {path}"
        ids.append(str(data["id"]))
    assert ids, "No Sigma rules found"
    assert len(ids) == len(set(ids)), "Duplicate Sigma rule IDs found"


def test_expectations_cover_complete_rule_corpus_matrix():
    expected = yaml.safe_load(
        (ROOT / "ci" / "expectations.yml").read_text(encoding="utf-8")
    )
    pairs = {
        (str(item["rule"]), item["corpus"])
        for item in expected["expectations"]
    }

    rule_ids = {
        str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])
        for path in _rule_files()
    }
    corpora = {
        str(path.relative_to(CORPUS))
        for path in _corpus_files()
    }
    required = {
        (rule_id, corpus)
        for rule_id in rule_ids
        for corpus in corpora
    }

    assert pairs == required, (
        f"Expectation matrix mismatch. Missing: {sorted(required - pairs)}; "
        f"stale: {sorted(pairs - required)}"
    )
