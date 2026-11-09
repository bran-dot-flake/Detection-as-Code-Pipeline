# Detection-as-Code Pipeline

A Detection-as-Code CI/CD lab that treats Sigma detections like software: rules
are versioned in Git, validated against positive and negative evidence, compiled
to Splunk SPL, verified against a live Splunk instance, and deployed as scheduled
saved-search alerts only after protected promotion controls pass.

The current detection set draws from two investigation sources:

- [Agent Tesla Malware Analysis and Detection Engineering](https://github.com/bran-dot-flake/Agent-Tesla-Malware-Analysis-and-Detection-Engineering)
- [Threat Hunting with Splunk - Hack The Box Writeup](https://github.com/bran-dot-flake/Threat-Hunting-with-Splunk-Hack-The-Box-Writeup)

## Current detections

| Rule | Type | Positive evidence | Expected |
|---|---|---|---:|
| AgentTesla-01 Self-Spawn | Case-scoped | Sysmon records `976934`, `976935` | 2 |
| AgentTesla-01 FTP Connection | Case-scoped | Sysmon record `977067` | 1 |
| AgentTesla-01 FTP Domain Lookup | IOC | Sysmon record `977063` | 1 |
| AgentTesla-01 IP-API Lookup | Case-scoped | Sysmon record `977057` | 1 |
| Executable Masquerading as PDF via Double Extension | Behavioral | Process at `09:28:07.170` | 1 |
| Executable in Downloads Spawning Windows Command Shell | Behavioral | Process at `09:28:55.870` | 1 |
| Local Account Creation via Net Utility | Behavioral | Process at `09:31:57.220` | 1 |
| PowerShell Execution Policy Bypass Argument | Behavioral | Process at `09:42:08.640` | 1 |
| Threat Hunt Application Form C2 Connection | Case-scoped | Network event at `09:28:09.378` | 1 |

The Agent Tesla source repository stores domains defanged; CI fixtures normalize
those values back to operational form for matching. The threat-hunt fixtures retain
the published event times and observed fields. Password material is redacted.

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

Feature branches are tested by pull-request workflows only. Push workflows run on
`main`, which prevents duplicate branch CI runs and keeps the private self-hosted
runner entirely out of pull-request execution.

## Evidence-backed detection families

### Agent Tesla

The four Agent Tesla rules are tied directly to the sanitized Sysmon evidence set:

- Self-spawn: records `976934` and `976935`
- FTP connection: record `977067`
- FTP-domain lookup: record `977063`
- IP-API lookup: record `977057`

Real near-misses include Explorer launching the sample and the malware connecting
to TCP/80 rather than FTP. Synthetic benign fixtures cover ordinary parent/child,
FTP, and DNS behavior.

### Threat Hunting with Splunk

#### PDF double-extension execution

The investigation observed:

```text
C:\Users\LetsDefend\Downloads\application_form.pdf.exe
```

The behavioral rule detects execution of an image ending in `.pdf.exe`.
The benign corpus includes a real PDF opened by Acrobat and an ordinary installer
from Downloads.

#### Downloads executable spawning cmd.exe

At `09:28:55.870`, the masquerading executable spawned:

```text
C:\Windows\System32\cmd.exe
ParentImage = C:\Users\LetsDefend\Downloads\application_form.pdf.exe
```

The rule requires `cmd.exe` plus a parent image located under a Downloads
directory. The benign corpus includes Explorer launching cmd.exe and a normal
installer executing from Downloads without spawning a shell.

#### Local account creation via Net utility

The investigation recorded:

```text
C:\Windows\system32\net1 user jumpadmin <REDACTED> /add
```

The detection requires `net.exe` or `net1.exe`, a `user` argument, and
`/add`. The benign corpus includes `net1 user` enumeration without account
creation.

The event proves the command was issued; it does not claim the account creation
succeeded or that the account received administrator membership.

#### PowerShell execution-policy Bypass

The investigation observed:

```text
powershell.exe -ep bypass
```

The rule covers the observed `-ep bypass` form and equivalent aliases used in
the hunt query. A benign baseline uses `-ExecutionPolicy RemoteSigned`.

Execution policy is not treated as a security boundary; this analytic is intended
as suspicious execution context, not proof of defense evasion by itself.

#### Case-scoped C2 connection

The investigation observed `application_form.pdf.exe` connecting to
`13.232.55.12` on destination port `30`.

The C2 rule intentionally requires all three observed indicators:

```text
image = application_form.pdf.exe
destination = 13.232.55.12
port = 30
```

The benign/near-miss corpus separately changes the process, destination, and port
to prove the full conjunction is required. This is an investigation-specific
analytic rather than a generic “port 30 is malicious” rule.

## Complete expectation matrix

`ci/expectations.yml` defines an expected count for every rule/corpus pair.
`tests/test_fixtures.py` fails CI if any pair is missing or stale.

Current coverage:

```text
9 Sigma rules
x
13 corpus files
=
117 explicit expectations
```

This means a fixture added for one investigation is automatically regression-tested
against every other detection.

## Regression demonstration

A temporary branch intentionally removed the Agent Tesla Self-Spawn rule's
`ParentImage` condition. The rule remained syntactically valid and still detected
the true positives, but it also detected the Explorer -> sample near-miss.

```text
Expected near-miss matches: 0
Observed near-miss matches: 1

Result: FAILED
Splunk compilation: SKIPPED
Deployment: BLOCKED
```

Failed demonstration run:

<https://github.com/bran-dot-flake/Detection-as-Code-Pipeline/actions/runs/42632208052>

This demonstrates why the pipeline tests detection behavior instead of treating
syntax validation as sufficient.

## Pull-request and promotion controls

The `main` branch is protected by an active GitHub ruleset:

- pull requests are required;
- `Validate and test Sigma rules` must pass;
- `Compile rules to Splunk SPL` must pass;
- branches must be up to date before merge;
- branch deletion and force pushes are blocked.

The workflow independently verifies that an automatic push-to-`main` deployment
is associated with a merged pull request. Manual workflow dispatch remains
available to redeploy the current trusted `main` revision.

The private Splunk runner is not used for pull-request code.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development flow.

## Live Splunk integration

The live test uses a dedicated `dac_test` index so test fixtures cannot trigger
the scheduled detections in `index=sysmon`.

The integration script:

1. posts the NDJSON corpus through the Splunk management REST API;
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

## Detection health telemetry

Deployment now stamps every managed Splunk saved search with lifecycle metadata:

```text
rule_id=<Sigma UUID>
commit=<Git commit deployed>
query_sha256=<hash of normalized deployed SPL>
```

After each deployment, and every six hours through the separate
`Detection Health` workflow, the self-hosted runner queries Splunk and produces
both Markdown and JSON health reports.

The health check verifies:

- every repository rule has a corresponding `DaC -` saved search;
- the saved search is enabled and scheduled;
- its deployed rule ID matches the repository rule;
- its deployed commit matches the current trusted `main` revision;
- the live SPL still matches the hash recorded at deployment time;
- recent saved-search execution history is available and the latest job is not in
  a failed/cancelled state;
- next-run, last-run, result-count, and scheduler state are captured for reporting.

Missing, disabled, unscheduled, stale, drifted, or failed detections make the
health job fail. A brand-new detection with no scheduler history yet is reported
as a warning instead of a false failure.

Reports are attached to GitHub Actions as:

```text
reports/splunk-health.md
reports/splunk-health.json
```

The Markdown report is also appended to the GitHub Actions job summary so health
can be reviewed without downloading the artifact.

## Splunk deployment

Passing detections are created or updated idempotently through the Splunk REST API
as scheduled alerts in the `search` app.

Current lab behavior:

```text
target index:       sysmon
test index:         dac_test
schedule:           every 5 minutes
search window:      previous 5 minutes
trigger condition:  result count > 0
deployment:         create or update by saved-search name
```

The GitHub environment stores `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN` as
secrets. Repository variables select the production/test indexes, lab TLS behavior,
and whether deployment is enabled.

## Run locally

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

The core CI/CD and health-monitoring paths are complete. Useful extensions now include:

- rollback/version recovery for deployed saved searches;
- alert-volume and false-positive telemetry from analyst outcomes;
- additional investigation-backed rule families;
- a second compilation/deployment target such as Microsoft Sentinel KQL.

## References

- <https://rsigma.io/guide/ci-cd/>
- <https://sigmahq.io/docs/>
- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions>
