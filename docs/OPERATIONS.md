# Operations and Recovery

## Trusted deployment

Changes are promoted through a protected `main` branch. Pull-request validation runs on GitHub-hosted runners; the private self-hosted runner is used only after a trusted revision reaches `main`.

The deployment sequence is:

```text
compile
  -> live Splunk test
  -> snapshot current managed state
  -> validate snapshot
  -> create/update desired searches
  -> disable managed searches absent from Git
  -> health verification
```

The Splunk environment uses:

- `SPLUNK_MANAGEMENT_URL` and `SPLUNK_TOKEN` as GitHub environment secrets;
- `SPLUNK_INDEX=sysmon` for deployed detections;
- `SPLUNK_TEST_INDEX=dac_test` for live CI fixtures;
- `SPLUNK_VERIFY_TLS=false` only for the isolated self-signed lab.

## Health

The `Detection Health` workflow runs every six hours and can also be dispatched manually from `main`.

It checks:

- each repository rule has a corresponding enabled/scheduled saved search;
- no Git-absent managed search remains enabled;
- deployed rule ID and Git commit metadata;
- deployed SPL hash drift;
- recent scheduler execution state.

Markdown and JSON reports are uploaded as workflow artifacts.

## Rollback

Every trusted deployment uploads a 30-day `splunk-rollback-backup` artifact containing the pipeline-owned fields of the currently deployed saved searches.

The manual `Rollback Splunk Detections` workflow requires:

1. the deployment workflow run ID containing the desired backup;
2. explicit confirmation;
3. execution from protected `main`.

Before restoring, the workflow takes another snapshot of the current state. It then restores the selected snapshot, disables any managed searches introduced after that snapshot, and verifies the live fields against the backup.

An empty snapshot is valid and represents a state with no active pipeline-managed detections.
