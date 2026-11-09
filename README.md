# Detection-as-Code Pipeline

A Detection-as-Code CI/CD lab that treats Sigma detections like software: rules
are versioned in Git, validated against investigation-backed positive and negative
evidence, compiled to Splunk SPL, verified against a live Splunk instance, and
deployed as scheduled saved-search alerts only after the promotion controls pass.

The current detection set is derived from my Agent Tesla malware analysis:

<https://github.com/bran-dot-flake/Agent-Tesla-Malware-Analysis-and-Detection-Engineering>

## Current detections

| Rule | Sigma ID | Positive evidence | Expected |
|---|---|---|---:|
| AgentTesla-01 Self-Spawn | `c8859ff7-c5c3-4975-9ebe-7b35d6a047f2` | Sysmon records `976934`, `976935` | 2 |
| AgentTesla-01 FTP Connection | `e308373e-277b-47f7-aa9e-2dbcbc61478b` | Sysmon record `977067` | 1 |
| AgentTesla-01 FTP Domain Lookup | `573a63f3-f985-4a43-be5e-dd7034444f44` | Sysmon record `977063` | 1 |
| AgentTesla-01 IP-API Lookup | `71e71ad1-dd8c-4e65-b4b7-9f5e11abf9ce` | Sysmon record `977057` | 1 |

The source evidence repository stores domains defanged. The CI fixtures normalize
those domain values back to their operational form so the Sigma matchers can be
tested while retaining the source event record IDs and surrounding fields.

## Pipeline

```text
feature branch
      |
      v
pull request
      |
      +-- fixture/schema validation
      +-- Sigma validation
      +-- positive / negative RSigma backtest
      +-- complete rule x corpus expectation matrix
      +-- Sigma -> Splunk SPL compilation
      |
      v
required checks pass
      |
      v
merge to protected main
      |
      +-- promotion gate verifies merged PR origin
      |
      v
self-hosted Debian Splunk runner
      |
      +-- download compiled SPL artifact
      +-- ingest isolated fixtures into index=dac_test
      +-- execute generated SPL against live Splunk
      |
      v
live integration passes
      |
      v
create/update scheduled alerts targeting index=sysmon
```

The private self-hosted runner never executes pull-request code. Pull requests use
GitHub-hosted runners for validation and compilation; live Splunk access occurs
only after a trusted revision reaches `main`.

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

### FTP Domain Lookup

The rule requires Sysmon Event ID 22 and the recovered FTP destination
`ftp.ritubohara.com`.

- Record `977063`: DNS lookup of the recovered FTP destination. Must match.
- Record `977057`: DNS lookup of `ip-api.com`. Must not match.
- Synthetic normal DNS activity: must not match.

This is intentionally a domain-specific IOC rule. Legitimate resolution of the
same domain remains a documented false-positive possibility.

### IP-API Lookup

The rule requires Sysmon Event ID 22, `ip-api.com`, and the analyzed executable
name.

- Record `977057`: sample -> DNS lookup of `ip-api.com`. Must match.
- Record `977063`: sample -> FTP-domain lookup. Must not match.
- Synthetic Chrome -> `ip-api.com`: must not match, proving that the process
  image constraint is required.

The packet capture separately recorded
`GET /line/?fields=hosting` to `ip-api.com`; that HTTP path is supporting
network evidence and is not claimed to be present in the Sysmon DNS event.

## Complete expectation matrix

`ci/expectations.yml` defines an expected match count for every rule/corpus pair,
and `tests/test_fixtures.py` fails CI if any pair is missing or stale.

Current coverage:

```text
4 Sigma rules
x
9 corpus files
=
36 explicit expectations
```

This makes new test data regression-sensitive across the entire detection set,
not only the rule it was originally added for.

## Regression demonstration

A temporary branch intentionally removed the Self-Spawn rule's `ParentImage`
condition. The rule remained syntactically valid and still detected the two
positive events, but it also detected record `976880` (Explorer -> sample).

```text
Expected near-miss matches: 0
Observed near-miss matches: 1

Result: FAILED
Splunk compilation: SKIPPED
Deployment: BLOCKED
```

Failed demonstration run:

<https://github.com/bran-dot-flake/Detection-as-Code-Pipeline/actions/runs/42632208052>

This demonstrates why the pipeline tests detection behavior rather than treating
syntax validation as sufficient.

## Pull-request and promotion controls

The `main` branch is protected by an active GitHub ruleset:

- pull requests are required;
- `Validate and test Sigma rules` must pass;
- `Compile rules to Splunk SPL` must pass;
- branches must be up to date before merge;
- branch deletion and force pushes are blocked.

The workflow independently verifies that an automatic push-to-`main` deployment
is associated with a merged pull request. Manual workflow dispatch is retained for
an explicit redeploy of the current trusted `main` revision.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development flow.

## Live Splunk integration

The live test uses a dedicated `dac_test` index so fixture events cannot trigger
the real scheduled detections in `index=sysmon`.

The script:

1. posts the NDJSON corpus through Splunk's management REST API;
2. tags each run with a unique `DaCTestRunId`;
3. maps fixture `EventID` to Splunk `EventCode`;
4. runs each generated SPL search through the live Splunk search API;
5. compares the returned count with the expected rule total.

A successful run proves:

```text
Sigma rule
  -> RSigma behavior test
  -> compiled SPL artifact
  -> real Splunk execution
  -> expected live result count
```

## Splunk deployment

Passing detections are created or updated idempotently through the Splunk REST API
as scheduled alerts in the `search` app.

Current lab behavior:

```text
target index:       sysmon
schedule:           every 5 minutes
search window:      previous 5 minutes
trigger condition:  result count > 0
deployment:         create or update by saved-search name
```

The GitHub environment stores `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN` as
secrets. Repository variables select `sysmon`, `dac_test`, TLS behavior for the
isolated lab, and whether deployment is enabled.

## Run locally

Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-conversion.txt
python -m pytest -q tests/test_fixtures.py
```

With RSigma 0.25.0 installed:

```bash
rsigma rule validate rules/sigma/
rsigma rule backtest \
  --rules rules/sigma/ \
  --corpus tests/sample-logs/ \
  --expectations ci/expectations.yml \
  --unexpected fail

python scripts/build_splunk.py
```

For the isolated Splunk lab:

```bash
export SPLUNK_MANAGEMENT_URL="https://127.0.0.1:8089"
export SPLUNK_TOKEN="<token>"
export SPLUNK_INDEX="dac_test"
export SPLUNK_VERIFY_TLS=false

python scripts/test_splunk_integration.py
```

Never commit the Splunk token. TLS verification is disabled only because this
isolated lab uses Splunk's default self-signed certificate.

## Next milestones

The core CI/CD pipeline is complete. Useful future extensions include detection
health telemetry, rollback/version metadata, additional malware cases, and
cross-platform compilation targets such as Sentinel KQL.

## References

- <https://rsigma.io/guide/ci-cd/>
- <https://sigmahq.io/docs/>
- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions>
