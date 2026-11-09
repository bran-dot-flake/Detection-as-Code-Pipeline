"""Focused lifecycle tests for deployment, health, snapshot, and rollback logic."""
import json
import sys
from pathlib import Path

from scripts import check_splunk_health as health
from scripts import deploy_splunk as deploy
from scripts import rollback_splunk as rollback
from scripts import snapshot_splunk as snapshot

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload or {}
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, entries=None):
        self.entries = entries or []
        self.posts = []
        self.headers = {}
        self.verify = True

    def get(self, url, params=None, timeout=None):
        return FakeResponse({"entry": self.entries})

    def post(self, url, data=None, params=None, timeout=None):
        self.posts.append({"url": url, "data": data or {}})
        return FakeResponse({"entry": []})

    def close(self):
        return None


def test_snapshot_supports_empty_managed_state(tmp_path, monkeypatch):
    output = tmp_path / "empty-snapshot.json"
    session = FakeSession(entries=[])

    monkeypatch.setenv("SPLUNK_MANAGEMENT_URL", "https://splunk.local:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "test-token")
    monkeypatch.setattr(snapshot.requests, "Session", lambda: session)
    monkeypatch.setattr(
        sys,
        "argv",
        ["snapshot_splunk.py", "--output", str(output)],
    )

    assert snapshot.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["searches"] == []
    assert payload["repository_commit"] == "empty"


def test_rollback_accepts_empty_snapshot(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "searches": [],
                "repository_commit": "empty",
            }
        ),
        encoding="utf-8",
    )

    loaded = rollback.load_snapshot(path)
    assert loaded["searches"] == []


def test_reconciliation_disables_only_enabled_searches_absent_from_git():
    session = FakeSession(
        entries=[
            {
                "name": "DaC - Current",
                "content": {"disabled": "0"},
            },
            {
                "name": "DaC - Removed",
                "content": {"disabled": "0"},
            },
            {
                "name": "DaC - Previously Retired",
                "content": {"disabled": "1"},
            },
            {
                "name": "Unmanaged Search",
                "content": {"disabled": "0"},
            },
        ]
    )

    stale = deploy.reconcile_removed_searches(
        session,
        "https://splunk.local:8089",
        "search",
        {"DaC - Current"},
    )

    assert stale == ["DaC - Previously Retired", "DaC - Removed"]
    assert len(session.posts) == 1
    assert "DaC%20-%20Removed" in session.posts[0]["url"]
    assert session.posts[0]["data"] == {"disabled": "1"}


def test_health_flags_only_enabled_git_absent_managed_searches():
    live = {
        "DaC - Current": {
            "content": {"disabled": "0", "is_scheduled": "1"}
        },
        "DaC - Orphan": {
            "content": {
                "disabled": "0",
                "is_scheduled": "1",
                "description": "Managed by Detection-as-Code-Pipeline; commit=abc",
            }
        },
        "DaC - Retired": {
            "content": {"disabled": "1", "is_scheduled": "1"}
        },
    }

    results = health.enabled_orphan_results(live, {"DaC - Current"})

    assert [item["name"] for item in results] == ["DaC - Orphan"]
    assert results[0]["status"] == "ERROR"
    assert results[0]["last_state"] == "ORPHANED"


def test_rollback_workflow_uses_real_github_expressions():
    workflow = (
        ROOT / ".github" / "workflows" / "rollback-splunk.yml"
    ).read_text(encoding="utf-8")

    assert "\\${{" not in workflow
    assert "${{ github.token }}" in workflow
    assert "${{ secrets.SPLUNK_TOKEN }}" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
