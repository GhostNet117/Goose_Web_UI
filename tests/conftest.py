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


from goose_web import profiles as _profiles  # noqa: E402

_REAL_ACCOUNT_HOME = _profiles.account_home   # before any test replaces it


@pytest.fixture
def real_account_home():
    """The product's own account_home. Every test otherwise gets an empty folder in its place (below), so the
    function itself would never run in the suite."""
    return _REAL_ACCOUNT_HOME


@pytest.fixture(scope="session")
def _empty_account_home(tmp_path_factory):
    return tmp_path_factory.mktemp("account-home-empty")


@pytest.fixture(autouse=True)
def _no_real_home_library(monkeypatch, _empty_account_home):
    """No test reads the developer's own home folder (spec 028). The native profile's library lists Goose's
    home-folder skills and recipes and the administrator's GOOSE_RECIPE_PATH; on a developer's machine those are
    real, so results would depend on who runs the tests. Every test gets an empty folder as that home and no
    GOOSE_RECIPE_PATH; the tests of the feature put their own folder in place."""
    from goose_web import profiles
    monkeypatch.setattr(profiles, "account_home", lambda: _empty_account_home)
    monkeypatch.delenv("GOOSE_RECIPE_PATH", raising=False)


def pytest_runtest_logreport(report):
    if not os.environ.get("GITHUB_ACTIONS") or not report.failed:
        return
    path, line = report.location[0], (report.location[1] or 0) + 1
    text = str(report.longrepr or "")
    tail = " | ".join(x.strip() for x in text.splitlines() if x.strip())[-900:]
    msg = f"{report.nodeid} ({report.when}): {tail}".replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"\n::error file={path},line={line}::{msg}", flush=True)


def _own_window_objects() -> tuple[str, str]:
    """The access lists of the window station and the desktop this test run sits on, as SDDL."""
    import ctypes
    from ctypes import wintypes
    u32, adv = ctypes.WinDLL("user32"), ctypes.WinDLL("advapi32")
    k32 = ctypes.WinDLL("kernel32")
    u32.GetProcessWindowStation.restype = u32.GetThreadDesktop.restype = wintypes.HANDLE
    adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                                         ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    u32.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.DWORD)]
    ws = u32.GetProcessWindowStation()
    buf, n = ctypes.create_unicode_buffer(256), wintypes.DWORD()
    u32.GetUserObjectInformationW(ws, 2, buf, ctypes.sizeof(buf), ctypes.byref(n))
    out = []
    for h in (ws, u32.GetThreadDesktop(k32.GetCurrentThreadId())):
        psd, text = ctypes.c_void_p(), wintypes.LPWSTR()
        if adv.GetSecurityInfo(h, 7, 4, None, None, None, None, ctypes.byref(psd)) != 0:
            out.append("")
            continue
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, 1, 4, ctypes.byref(text), None)
        out.append(text.value or "")
    if buf.value.lower() != "winsta0":
        # Not a signed-in session (a runner that is itself a service): there the product names the containers it
        # starts, by design, and a test that does not delete its container leaves that entry. Entries of single
        # containers are not what this guards.
        import re
        out = [re.sub(r"\(A;[^)]*;;;S-1-15-2(-\d+){7}\)", "", x) for x in out]
    return out[0], out[1]


@pytest.fixture(scope="session", autouse=True)
def _the_session_is_left_as_it_was():
    """The window station and desktop of whoever runs the tests - a person's signed-in session - are not the tests'
    to change. On 2026-11-14 a test record with the stand-in SID S-1-15-2-1 made the product take the entries of
    ALL APPLICATION PACKAGES off both. The product no longer can (sandbox.dismiss); this makes the run fail if
    anything ever does again."""
    import sys
    if sys.platform != "win32":
        yield
        return
    before = _own_window_objects()
    yield
    if not all(before):     # could not be read: nothing to compare with, and that is said, not passed over
        import warnings
        warnings.warn("the access lists of this session's window station and desktop could not be read: the run "
                      "was NOT checked for leaving them as they were")
        return
    after = _own_window_objects()
    assert after == before, ("the test run changed the access list of the window station or desktop it ran on:\n"
                             f"before {before}\nafter  {after}")
