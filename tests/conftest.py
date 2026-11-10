"""Test-suite wide hooks.

On GitHub Actions every failed test is also reported as an `::error` workflow annotation (file, line, test id and
the last lines of the failure), so a CI failure can be read from the public check-run annotations without access to
the job log."""
import os

import pytest


@pytest.fixture(autouse=True)
def _no_model_download(monkeypatch):
    """No test downloads the Prompt Guard package from the network (spec 018): the download path fails loudly unless
    a test injects its own httpx.MockTransport into goose_web.guardmodel._TRANSPORT."""
    import httpx
    from goose_web import guardmodel

    def refuse(request):
        raise AssertionError(f"network access in a test: {request.url}")
    monkeypatch.setattr(guardmodel, "_TRANSPORT", httpx.MockTransport(refuse))


def pytest_runtest_logreport(report):
    if not os.environ.get("GITHUB_ACTIONS") or not report.failed:
        return
    path, line = report.location[0], (report.location[1] or 0) + 1
    text = str(report.longrepr or "")
    tail = " | ".join(x.strip() for x in text.splitlines() if x.strip())[-900:]
    msg = f"{report.nodeid} ({report.when}): {tail}".replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"\n::error file={path},line={line}::{msg}", flush=True)
