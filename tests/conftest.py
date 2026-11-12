"""Test-suite wide hooks.

On GitHub Actions every failed test is also reported as an `::error` workflow annotation (file, line, test id and
the last lines of the failure), so a CI failure can be read from the public check-run annotations without access to
the job log."""
import os

import pytest

# No test may change the developer's own Goose profile. Since 1.20.0 a real gateway applies Goose's security settings
# to its administrator's native Goose profile when it starts, and tests that start a real gateway (test_tls_logs)
# initialise it with the default native root, which is the real %APPDATA%\Block\goose. This switches that off for
# every gateway the test session starts (child processes inherit it; the environment beats config.yaml). Tests of the
# native apply itself use temporary profiles and turn it on in their own settings.
os.environ["GOOSE_WEB__GUARD__NATIVE_PROFILE"] = "false"


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
