## Detection change

### What changed?

<!-- Briefly describe the detection or pipeline change. -->

### Evidence and expected behavior

- [ ] Positive fixture(s) represent behavior the rule should detect.
- [ ] Negative / near-miss fixture(s) represent behavior the rule should ignore.
- [ ] `ci/expectations.yml` reflects the intended match counts.
- [ ] No secrets, credentials, or unsanitized investigation data are included.

### Validation

- [ ] `Validate and test Sigma rules` passes.
- [ ] `Compile rules to Splunk SPL` passes.
- [ ] Generated SPL was reviewed when detection logic changed.

> Live Splunk testing and deployment occur only after the change reaches `main`.
