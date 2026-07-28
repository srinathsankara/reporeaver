"""Additional workflow analyzer tests — uncovered branches."""
import pytest
from reporeaver.analyzers.workflow_analyzer import WorkflowAnalyzer
from reporeaver.models import FileEntry


@pytest.fixture
def analyzer():
    return WorkflowAnalyzer()


def _entry(content, path=".github/workflows/test.yml"):
    return FileEntry(path=path, size=len(content), hash_sha256="x", is_text=True)


class TestShouldAnalyze:
    def test_workflow_file(self):
        e = _entry("name: ci", ".github/workflows/ci.yml")
        assert WorkflowAnalyzer().should_analyze(e)

    def test_non_workflow(self):
        e = _entry("hello", "README.md")
        assert not WorkflowAnalyzer().should_analyze(e)

    def test_yaml_extension(self):
        e = _entry("hello", ".github/workflows/deploy.yaml")
        assert WorkflowAnalyzer().should_analyze(e)


class TestSecretsExposure:
    def test_secret_env_var(self, analyzer):
        content = """
name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.AWS_SECRET_KEY }}
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("secret" in t.lower() for t in titles)

    def test_github_token(self, analyzer):
        content = """
name: CI
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.GITHUB_TOKEN }}
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("secret" in t.lower() for t in titles)


class TestScheduledTriggers:
    def test_cron_trigger(self, analyzer):
        content = """
name: Nightly
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("schedule" in t.lower() or "cron" in t.lower() for t in titles)


class TestSelfHostedRunner:
    def test_self_hosted(self, analyzer):
        content = """
name: CI
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hello
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("self-hosted" in t.lower() for t in titles)


class TestReusableWorkflows:
    def test_cross_org_reusable(self, analyzer):
        content = """
name: CI
jobs:
  call:
    uses: octo-org/thisrepo/.github/workflows/workflow.yml@main
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("reusable" in t.lower() for t in titles)

    def test_official_action_not_flagged(self, analyzer):
        content = """
name: CI
jobs:
  test:
    uses: actions/checkout@v3
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert not any("reusable" in t.lower() for t in titles)


class TestArtifactChain:
    def test_upload_download_chain(self, analyzer):
        content = """
name: CI
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v3
  deploy:
    steps:
      - uses: actions/download-artifact@v3
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("artifact" in t.lower() for t in titles)


class TestDispatchTriggers:
    def test_workflow_dispatch(self, analyzer):
        content = """
name: Manual
on:
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("dispatch" in t.lower() for t in titles)
