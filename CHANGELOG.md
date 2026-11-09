# Changelog

## 1.0.0

Initial complete Detection-as-Code lifecycle release.

- Nine evidence-backed Sigma detections across two investigation sources.
- Positive, benign, and near-miss regression corpus with 117 explicit expectations.
- Protected pull-request validation and Sigma-to-Splunk compilation.
- Live Splunk integration testing in a dedicated test index.
- Idempotent saved-search deployment through the Splunk REST API.
- Git-as-desired-state reconciliation for retired detections.
- Scheduled deployment health and query-drift monitoring.
- Pre-deployment snapshots and verified manual rollback, including empty-state recovery.
