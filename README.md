# Detection-as-Code Pipeline

A detection-engineering CI/CD lab that treats Sigma rules like software: keep the
rules in Git, validate them on every change, replay known-positive and
known-negative events, compile passing detections to Splunk SPL, and optionally
promote them to a private Splunk lab.

The current tests use investigation-backed rules and selected Sysmon evidence from
my Agent Tesla malware analysis.

## Current detections

| Rule | Sigma ID | Positive evidence | Expected |
|---|---|---|---:|
| AgentTesla-01 Self-Spawn | `c8859ff7-c5c3-4975-9ebe-7b35d6a047f2` | Sysmon records `976934`, `976935` | 2 |
| AgentTesla-01 FTP Connection | `e308373e-277b-47f7-aa9e-2dbcbc61478b` | Sysmon record `977067` | 1 |

Source investigation:
<https://github.com/bran-dot-flake/Agent-Tesla-Malware-Analysis-and-Detection-Engineering>

## Pipeline

```text
Sigma rules in Git
       |
       v
GitHub Actions
       |
       +-- fixture/schema checks
       +-- Sigma validation
       +-- RSigma backtest
       |     real positives      -> MUST MATCH
       |     real near-misses    -> MUST NOT MATCH
       |     synthetic benign    -> MUST NOT MATCH
       |
       +-- only if every expectation passes
       v
Sigma CLI + Splunk Windows pipeline
       |
       v
Splunk SPL artifact
       |
       +-- optional later: self-hosted runner -> Splunk REST API
```

A failed expectation stops the pipeline before SPL is published or deployment can
occur.

## Evidence-backed test cases

### Self-Spawn

The rule requires Sysmon Event ID 1 with both `Image` and `ParentImage`
ending in the analyzed sample filename.

- Records `976934` and `976935`: sample -> sample. Must match.
- Record `976880`: Explorer -> sample. Must not match.
- Synthetic parent/child baseline events: must not match.

### FTP Connection

The rule requires Sysmon Event ID 3, the analyzed sample filename, TCP, and
destination port 21.

- Record `977067`: sample -> TCP/21. Must match.
- Record `977060`: same process -> TCP/80. Must not match.
- Synthetic normal FTP clients -> TCP/21: must not match because the image does
  not match the analyzed sample.

The selected real events are adapted from
`cases/Agent Tesla/evidence/sysmon-selected-events.json`. Values needed by the
matcher are represented with JSON-native types in the CI fixtures; the event
record IDs and observed field values are retained.

## Complete expectation matrix

`ci/expectations.yml` explicitly defines an expected count for **every
rule/corpus pair**. The Python hygiene test verifies that the matrix is complete,
so adding a rule or fixture without defining its expected behavior fails CI before
the backtest even starts.

With 2 rules and 6 corpus files, the current matrix has 12 expectations.

## Regression demonstration

A temporary branch intentionally removed the Self-Spawn rule's `ParentImage`
condition. The rule still detected the two true-positive child events, but it also
detected record `976880` (Explorer -> sample):

```text
Expected near-miss matches: 0
Observed near-miss matches: 1

Backtest: 2/3 expectations passed
Result: FAILED
Splunk compilation: SKIPPED
```

This demonstrates the core Detection-as-Code control: a syntactically valid rule
can still be rejected because its behavior regressed.

Failed demonstration run:
<https://github.com/bran-dot-flake/Detection-as-Code-Pipeline/actions/runs/42632208052>

## CI behavior

The GitHub Actions workflow runs on pushes and pull requests:

1. Validate NDJSON fixtures and the full expectation matrix.
2. Validate Sigma syntax/structure with RSigma.
3. Backtest every rule against every corpus file.
4. Fail if a required positive is missed or a known-negative event fires.
5. Only after tests pass, compile all rules to Splunk SPL with the
   `splunk_windows` processing pipeline.
6. Publish the SPL files and build manifest as a GitHub Actions artifact.

The optional Splunk deployment job is disabled unless repository variable
`ENABLE_SPLUNK_DEPLOY` is explicitly set to `true`.

## Run locally

Python 3.12+:

```bash
python -m pip install -r requirements.txt -r requirements-conversion.txt
python -m pytest -q tests/test_fixtures.py
```

Install RSigma 0.25.0, then:

```bash
rsigma rule validate rules/sigma/
rsigma rule backtest \
  --rules rules/sigma/ \
  --corpus tests/sample-logs/ \
  --expectations ci/expectations.yml \
  --unexpected fail
python scripts/build_splunk.py
python scripts/deploy_splunk.py
```

`deploy_splunk.py` is a dry run unless `--live` is supplied.

## Optional Splunk deployment

For a private Splunk Enterprise lab:

1. Ingest Sysmon data and verify generated SPL against your field mappings.
2. Create a limited-privilege Splunk API token.
3. Register a GitHub self-hosted Linux runner that can reach Splunk's management
   API on HTTPS port 8089. Do not expose that management port publicly.
4. Configure the `splunk-lab` GitHub environment and secrets
   `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN`.
5. Set repository variable `ENABLE_SPLUNK_DEPLOY=true`.

Only a trusted push to `main`, after validation, backtesting, and conversion
pass, can reach the deployment job.

## Next milestones

- Add the DNS/IP-API Agent Tesla rules with real positive/near-miss fixtures.
- Add a Splunk integration test that executes compiled SPL against representative
  Sysmon data.
- Deploy passing saved searches to a private Splunk lab.
- Add detection-health telemetry and rollback handling.

## References

- <https://rsigma.io/guide/ci-cd/>
- <https://sigmahq.io/docs/>
- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions>
