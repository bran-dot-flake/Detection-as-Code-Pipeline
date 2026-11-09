# Detection-as-Code Pipeline

A small, reproducible detection-engineering lab: version Sigma rules, validate
them, replay malicious/benign sample logs, convert passing rules into Splunk SPL,
and optionally deploy scheduled Splunk saved searches.

## Architecture

```text
Sigma YAML in Git
       |
       v
GitHub Actions (push / pull request)
       |
       +-- Parse + validate rule (RSigma)
       |
       +-- Backtest against malicious and benign event fixtures
       |       malicious: matches expected, benign: zero matches
       |
       +-- Convert with Sigma CLI + Sysmon processing pipeline
       |
       v
SPL artifact (downloadable from GitHub Actions)
       |
       +-- [optional, main only] self-hosted runner -> Splunk REST API
       |                                    -> scheduled saved searches
       v
Future: monitor schedules, execution errors, true/false positives
```

The included PowerShell detection and events are **synthetic demo content**.
They do not constitute evidence from an actual investigation.

## First run: no Splunk required

1. Create a GitHub repository, unpack this starter, commit everything, and push to
   `main` (or any feature branch). Each push will run the checks.
2. Open **GitHub > Actions > Detection as Code**. The pipeline validates rules,
   backtests example events, converts to SPL, and publishes an artifact named
   `splunk-detections-<commit SHA>` **if all tests pass**.
3. Download the artifact and inspect the `.spl` query and `manifest.json`.
4. Try editing the rule to match a benign command; CI should turn red. Revert it.

This artifact is a compiled **deployment candidate**, not a deployed Splunk alert.

## Run the tests locally

Python 3.12+:

```bash
python -m pip install -r requirements.txt -r requirements-conversion.txt
python -m pytest -q tests/test_fixtures.py
```

Install the RSigma binary from <https://rsigma.io/getting-started/installation/>
(pin to `0.25.0` to match CI), then:

```bash
rsigma rule validate rules/sigma/
rsigma rule backtest --rules rules/sigma/ \
  --corpus tests/sample-logs/ \
  --expectations ci/expectations.yml \
  --unexpected fail
python scripts/build_splunk.py
python scripts/deploy_splunk.py
```

By default, `deploy_splunk.py` is a **dry run**. No Splunk account is needed for
these local commands except actual deployment with `--live`.

## How a test is defined

The rule has a stable UUID. `tests/sample-logs/malicious/powershell_encoded.ndjson`
has **3 known-positive** process events; `tests/sample-logs/benign/normal_admin.ndjson`
has **5 known-negative** process events. `ci/expectations.yml` requires **exactly
3** and **exactly 0** rule matches, respectively. Any mismatch fails CI.

These tests evaluate the Sigma rule using RSigma. They do **not** prove that the
translated SPL works against your exact Splunk field mappings or production log
sources. Once you have Splunk, add an integration test that ingests representative
Sysmon events and runs the compiled SPL against them before enabling deployment.

## Optional: deploy to a private Splunk lab

Splunk Enterprise trial supports alerting; **perpetual Splunk Free does not**.
Use a trial or eligible Developer license for a nonproduction lab.

1. Create a Splunk Enterprise lab and configure Sysmon event ingestion.
2. Confirm your index/source/field mapping is compatible with the generated SPL.
   The `sysmon` processing pipeline maps Sigma process creation events to Sysmon
   Event ID 1, but **does not ensure your actual index is searched**.
3. Create a limited-privilege Splunk API token with rights to manage the saved
   searches in your chosen app. Install a trusted TLS certificate or configure
   the runner to trust your lab CA.
4. Install and register a GitHub **self-hosted Linux runner** that can access the
   Splunk management API over HTTPS port 8089. Add the `splunk-lab` runner label.
   Do not open port 8089 to the public internet.
5. In GitHub, configure environment `splunk-lab` (optionally require review), add
   secrets `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN`, and set the repository variable
   `ENABLE_SPLUNK_DEPLOY` to `true`.
6. Only pushes to **main**, after CI tests and conversion pass, can deploy.

The deployment script creates or updates scheduled saved searches via Splunk's
REST API. It does not delete removed rules, manage permissions/owners, handle
rollback, suppress duplicates, or measure detection quality. Those are next
milestones. The script's initial schedule is every 5 minutes; review and tune
before relying on it. **Do not enable live deployment from unreviewed commits.**

## Extend with investigation-backed detections

1. Import your existing Sigma rules into `rules/sigma/` (keep UUIDs stable).
2. Export minimal, anonymized event examples matching the fields your rules use;
   put malicious and benign lines in `tests/sample-logs/` as NDJSON.
3. Add expectations **for each rule and each corpus file** you want to assert.
4. Run backtests and inspect the compiled SPL, then add Splunk integration tests.
5. Keep real user data, secrets, credentials, and full raw investigation dumps
   out of public Git repositories.

## Versioning and safety

- GitHub Actions runs on every commit pushed to GitHub and on PRs; conversion is gated by tests.
- Promotion to a live SIEM is off by default, needs secrets, and runs only on a
  private lab runner. PR code never runs on that self-hosted runner.
- Protect `main`: require passing checks and review before merging.
- A clean backtest only measures behavior **against the included sample corpus**.
  It is not proof of low false positive rates on all benign activity.

## References

- <https://rsigma.io/guide/ci-cd/>
- <https://sigmahq.io/docs/>
- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions>
- <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configure-splunk-licenses/about-splunk-free>
