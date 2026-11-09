The pipeline is GitHub Actions (`.github/workflows/detections.yml`).
`expectations.yml` uses RSigma corpus-relative paths. Edit expectations when you
add rules or change fixture sets; otherwise CI should fail on missing expected
matches or unexpected matches in the benign corpus.
