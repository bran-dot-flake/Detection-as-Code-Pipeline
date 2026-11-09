# Detection-as-Code Pipeline

A detection-engineering CI/CD lab that treats Sigma rules like software: keep the
rule in Git, validate it on every change, replay known-positive and known-negative
events, compile passing detections to Splunk SPL, and optionally promote them to a
private Splunk lab.

The first production-style test case is taken from my Agent Tesla malware analysis
rather than a synthetic detection.

## Current detection

**AgentTesla-01 Self-Spawn**  
Sigma ID: `c8859ff7-c5c3-4975-9ebe-7b35d6a047f2`

The rule detects Sysmon Event ID 1 when both `Image` and `ParentImage` end with
the analyzed sample filename. The investigation recorded two matching child-process
events:

- Event record `976934` — PID 2608, parent PID 5736
- Event record `976935` — PID 2628, parent PID 5736

The same evidence set also contains a useful near-miss: record `976880`, where
Explorer launched the sample. That event must **not** match because the parent image
is `explorer.exe`.

Source investigation:
<https://github.com/bran-dot-flake/Agent-Tesla-Malware-Analysis-and-Detection-Engineering>

## Pipeline

```text
Sigma rule in Git
      |
      v
GitHub Actions
      |
      +-- fixture/schema checks
      |
      +-- Sigma validation
      |
      +-- RSigma backtest
      |      2 real Agent Tesla positives -> MUST MATCH
      |      1 real Agent Tesla near-miss  -> MUST NOT MATCH
      |      3 synthetic benign events     -> MUST NOT MATCH
      |
      +-- only if all tests pass
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

## Test corpus

| Corpus | Source | Expected matches | Purpose |
|---|---|---:|---|
| `malicious/agenttesla_self_spawn.ndjson` | Sanitized AgentTesla-01 Sysmon evidence | 2 | Prove the rule is loud on the observed behavior |
| `nonmatching/agenttesla_initial_launch.ndjson` | Sanitized AgentTesla-01 Sysmon evidence | 0 | Prove the full parent/child condition is required |
| `benign/normal_parent_child.ndjson` | Synthetic baseline | 0 | Catch obvious false-positive regressions |

The real fixtures preserve the selected fields from
`cases/Agent Tesla/evidence/sysmon-selected-events.json` in the source
investigation. `$CASE` is the same sanitized case-root alias used there.

The benign events are deliberately marked synthetic. Passing them does **not**
prove the rule has a low false-positive rate on a real enterprise environment; it
only gives the pipeline a repeatable regression baseline.

## CI behavior

The GitHub Actions workflow runs on pushes and pull requests:

1. Validate that the NDJSON fixtures are well formed.
2. Validate Sigma syntax and structure with RSigma.
3. Backtest the rule against every corpus file using `ci/expectations.yml`.
4. Stop immediately if a required positive is missed or an unexpected event fires.
5. If tests pass, compile the rule to Splunk SPL with the
   `splunk_windows` processing pipeline.
6. Publish the SPL and build manifest as a GitHub Actions artifact.

The optional Splunk deployment job is disabled unless the repository variable
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

1. Ingest Sysmon data and verify the generated SPL against your field mappings.
2. Create a limited-privilege Splunk API token.
3. Register a GitHub self-hosted Linux runner that can reach Splunk's management
   API on HTTPS port 8089. Do not expose that management port publicly.
4. Configure the `splunk-lab` GitHub environment and secrets
   `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN`.
5. Set repository variable `ENABLE_SPLUNK_DEPLOY=true`.

Only a trusted push to `main`, after validation, backtesting, and conversion pass,
can reach that deployment job.

## Next milestones

- Intentionally weaken the Agent Tesla rule and verify CI blocks the regression.
- Add another investigation-backed Sigma rule and its own positive/negative corpus.
- Add a Splunk integration test that executes compiled SPL against representative
  Sysmon data.
- Deploy passing saved searches to a private Splunk lab.
- Add detection health/telemetry and rollback handling.

## References

- <https://rsigma.io/guide/ci-cd/>
- <https://sigmahq.io/docs/>
- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions>
