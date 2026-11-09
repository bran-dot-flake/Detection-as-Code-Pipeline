# Testing Model

The pipeline tests detections at three levels.

## Fixture and lifecycle tests

`pytest` validates:

- corpus structure and unique Sigma IDs;
- complete rule × corpus expectation coverage;
- desired-state reconciliation behavior;
- empty-state snapshot and rollback support;
- orphaned managed-search health detection;
- rollback workflow guardrails.

## Sigma behavior tests

RSigma evaluates every Sigma rule against every NDJSON corpus using `ci/expectations.yml`.

Current coverage:

```text
9 rules × 13 corpora = 117 explicit expectations
```

The corpus combines investigation-backed positive/near-miss events with synthetic benign baselines. Unexpected matches fail CI.

## Live Splunk integration

After merge, compiled SPL is executed against a real Splunk Enterprise instance using the dedicated `dac_test` index.

Each integration run receives a unique `DaCTestRunId`, allowing the pipeline to verify only the events ingested for that run. The deployment job proceeds only when each compiled search returns its expected count.

Production saved searches target `index=sysmon`; test fixtures remain isolated in `index=dac_test`.
