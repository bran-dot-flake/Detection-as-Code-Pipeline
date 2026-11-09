# Detection-as-Code Pipeline

A Splunk-focused Detection-as-Code pipeline that treats Sigma detections like software: versioned, tested, reviewed, compiled, verified against a live SIEM, deployed from a protected branch, monitored for drift, and recoverable to a previous state.

[![Detection as Code](https://github.com/bran-dot-flake/Detection-as-Code-Pipeline/actions/workflows/detections.yml/badge.svg)](https://github.com/bran-dot-flake/Detection-as-Code-Pipeline/actions/workflows/detections.yml)

## Overview

The project demonstrates a complete detection lifecycle rather than only storing detection rules.

```text
Sigma rules
    |
    v
Evidence-backed tests
    |
    v
Protected pull request
    |
    v
Sigma -> Splunk SPL
    |
    v
Live Splunk verification
    |
    v
Snapshot -> Deploy -> Reconcile
    |
    v
Health / drift monitoring
    |
    v
Manual rollback
```

Git is the desired state. Rules removed from the repository are disabled in Splunk rather than deleted, preserving history while keeping the active deployment aligned with source control.

## What it includes

| Capability | Implementation |
|---|---|
| Detection source | Sigma |
| Target SIEM | Splunk Enterprise |
| CI/CD | GitHub Actions |
| Detection tests | Positive, benign, and near-miss event fixtures |
| Regression coverage | Complete rule × corpus expectation matrix |
| Live validation | Compiled SPL executed against a dedicated `dac_test` index |
| Promotion | Protected `main` branch with required checks |
| Deployment | Idempotent Splunk REST API create/update |
| Desired-state reconciliation | Git-absent managed searches are disabled |
| Health | Schedule, execution state, version metadata, and SPL drift |
| Recovery | Pre-deploy snapshots and manual verified rollback |

## Current coverage

```text
9 Sigma detections
13 event corpora
117 explicit rule/corpus expectations
2 investigation sources
```

The detection set is derived from:

- [Agent Tesla Malware Analysis and Detection Engineering](https://github.com/bran-dot-flake/Agent-Tesla-Malware-Analysis-and-Detection-Engineering)
- [Threat Hunting with Splunk](https://github.com/bran-dot-flake/Threat-Hunting-with-Splunk-Hack-The-Box-Writeup)

The rules include both investigation-specific analytics and more reusable behavioral detections.

## Deployment model

Pull requests run only on GitHub-hosted runners. Code is allowed onto the private Splunk runner only after the required checks pass and the change reaches protected `main`.

Before each deployment, the current managed Splunk configuration is saved as a rollback artifact. After deployment, the pipeline verifies the live saved searches and records health metadata. A separate scheduled workflow checks the deployed state every six hours.

## Repository layout

```text
rules/sigma/          Sigma detections
tests/sample-logs/    Positive, benign, and near-miss fixtures
ci/expectations.yml   Complete expected-match matrix
scripts/              Build, test, deploy, health, snapshot, and rollback tooling
.github/workflows/    CI/CD, health, and rollback workflows
docs/                 Detection, testing, and operations notes
```

## Documentation

- [Detections](docs/DETECTIONS.md)
- [Testing model](docs/TESTING.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Contributing](CONTRIBUTING.md)

## Design choices

- Test evidence is kept separate from the production `sysmon` index.
- The self-hosted runner is never used for pull-request code.
- Managed searches are disabled rather than deleted when removed from Git.
- Rollback is manual and verified; it is not triggered automatically.
- TLS verification is disabled only in the isolated lab because Splunk uses a self-signed certificate.

## Status

The v1.0 scope is the complete Splunk detection lifecycle: author, test, review, compile, verify, deploy, reconcile, monitor, and recover.
