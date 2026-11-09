# Contributing

Detection changes should be developed on a feature branch and merged into `main`
through a pull request.

## Workflow

1. Create a branch such as `detection/<short-name>` or `pipeline/<short-name>`.
2. Add or update the Sigma rule.
3. Add positive and negative/near-miss fixtures.
4. Update the complete rule × corpus expectation matrix.
5. Open a pull request.
6. Merge only after the validation and SPL compilation checks pass.
7. After merge, the pipeline verifies the compiled SPL against the private Splunk
   lab and deploys the approved saved searches.

Direct pushes to `main` are not valid promotion events for automatic deployment.
The workflow independently verifies that a push to `main` is associated with a
merged pull request. Manual workflow dispatch remains available to redeploy the
current trusted `main` revision.

The private self-hosted Splunk runner is never used for pull-request code.
