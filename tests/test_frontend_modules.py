"""Static checks of the browser app's ES modules (no browser or Node needed).

Every relative `import { a, b } from './x.js'` must point at an existing file that exports each imported
name. A missing export only fails at runtime in the browser, which no other test would notice (spec 008
moved `pillSelect` from views/chat.js into chatoptions.js)."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import goose_web

JS = Path(goose_web.__file__).parent / "static" / "js"
IMPORT_RE = re.compile(r"import\s*\{([^}]*)\}\s*from\s*'(\.{1,2}/[^']+)'")
EXPORT_DECL_RE = re.compile(r"export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)")
EXPORT_LIST_RE = re.compile(r"export\s*\{([^}]*)\}")


def _exports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    names = set(EXPORT_DECL_RE.findall(text))
    for group in EXPORT_LIST_RE.findall(text):
        for part in group.split(","):
            part = part.strip()
            if part:
                names.add(part.split(" as ")[-1].strip())
    return names


MODULES = sorted(JS.rglob("*.js"))


@pytest.mark.parametrize("module", MODULES, ids=lambda p: p.relative_to(JS).as_posix())
def test_relative_imports_resolve(module: Path):
    text = module.read_text(encoding="utf-8")
    for names, spec in IMPORT_RE.findall(text):
        target = (module.parent / spec).resolve()
        assert target.is_file(), f"{module.name}: {spec} does not exist"
        exported = _exports(target)
        for name in (n.strip().split(" as ")[0].strip() for n in names.split(",")):
            if name:
                assert name in exported, f"{module.name}: {spec} does not export {name}"


def test_new_chat_options_module():
    """Spec 008: the New chat screen and the chat header share the per-chat option helpers."""
    exported = _exports(JS / "chatoptions.js")
    assert {"MODES", "pillSelect", "knownEfforts", "rememberEffortOptions",
            "loadNewChatOptions", "applyNewChatOptions"} <= exported
    home = (JS / "views" / "home.js").read_text(encoding="utf-8")
    assert "applyNewChatOptions" in home and "await applyChoice(chat)" in home
    # the options are applied before the first prompt is sent
    assert home.index("await applyChoice(chat)") < home.index("chat.send(blocks)")
    modes = re.findall(r"value: '(\w+)'", (JS / "chatoptions.js").read_text(encoding="utf-8").split("EFFORTS")[0])
    assert modes == ["auto", "approve", "smart_approve", "chat"]   # Goose's GooseMode variants


# ---------------------------------------------------------------- security assessment 2026-11-09, slice D
def _js(rel: str) -> str:
    return (JS / rel).read_text(encoding="utf-8")


def test_markdown_sanitizer_drops_layout_attributes():
    """D-1/D-7: untrusted markdown keeps no class (except language-* on <code>), id, name, style or hidden."""
    md = _js("markdown.js")
    assert "uponSanitizeAttribute" in md and "LANG_CLASS" in md and "node.nodeName === 'CODE'" in md
    forbid = re.search(r"FORBID_ATTR:\s*\[([^\]]*)\]", md).group(1)
    for attr in ("style", "id", "name", "hidden"):
        assert f"'{attr}'" in forbid, attr
    css = (JS.parent / "css" / "app.css").read_text(encoding="utf-8")
    rule = re.search(r"^\.md \{([^}]*)\}", css, re.M).group(1)
    assert "contain: layout paint" in rule and "position: relative" in rule


def test_markdown_code_blocks_are_flattened_before_copy():
    """D-2: every code block is reset to plain text (any size, streaming or final) before highlighting."""
    md = _js("markdown.js")
    body = md.split("export function decorate", 1)[1].split("\nexport function", 1)[0]
    assert "code.textContent = code.textContent;" in body
    assert body.index("code.textContent = code.textContent;") < body.index("if (final)")
    assert "copyText(code.innerText || code.textContent" in body


def test_markdown_images_block_protocol_relative():
    """D-6: //host/x and /\\host/x are remote images."""
    md = _js("markdown.js")
    assert "isLocalImageSrc" in md and r"/^\/(?![\/\\])/" in md and "origin === location.origin" in md


def test_login_error_codes_are_mapped():
    """D-3: the login page shows fixed text for known codes only, never the URL parameter itself."""
    login = _js("views/login.js")
    assert "decodeURIComponent" not in login and "loginErrorText(r.query.error)" in login
    known = set(re.findall(r"\['(\w+)',", login.split("LOGIN_ERRORS", 1)[1].split("]);", 1)[0]))
    root = JS.parent.parent
    server = (root / "api.py").read_text(encoding="utf-8") + (root / "auth.py").read_text(encoding="utf-8")
    codes = set(re.findall(r"login\?error=(\w+)", server)) | set(re.findall(r"\bfail\(\"(\w+)\"\)", server))
    codes |= set(re.findall(r"AuthError\(\"((?:oidc_|unknown_provider)\w*)\"", server))
    assert codes and codes <= known, codes - known


def test_router_survives_malformed_escapes():
    """D-3: a bad %-escape in the hash falls back to the home route instead of throwing."""
    router = _js("router.js")
    assert "malformed: true" in router and "catch" in router.split("parse(", 1)[1].split("current()", 1)[0]
    node = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    if not Path(node).is_file():
        pytest.skip("node not available")
    script = ("globalThis.window={addEventListener(){}};globalThis.location={hash:''};"
              f"const {{router}}=await import({json.dumps((JS / 'router.js').as_uri())});"
              "console.log(JSON.stringify([router.parse('#/chat/%'),router.parse('#/login?error=%25'),router.parse('#/chat/a%20b')]));")
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    bad, err, ok = json.loads(r.stdout.strip().splitlines()[-1])
    assert bad["view"] == "" and bad["malformed"] is True and bad["query"] == {}
    assert err["view"] == "login" and err["query"] == {"error": "%"}
    assert ok["args"] == ["a b"]


def test_app_bridge_confirms_every_call():
    """D-4: grid apps need a confirmation for every tools/call and resources/read, not a 4-name deny-list."""
    apps = _js("views/apps.js")
    assert "confirmAppCalls: true" in apps and "confirmSensitiveTools" not in apps
    tools = apps.split("'tools/call': async", 1)[1].split("'resources/read'", 1)[0]
    res = apps.split("'resources/read': async", 1)[1].split("'ui/message'", 1)[0]
    assert "await consent('tool:'" in tools and tools.index("await consent(") < tools.index("rpc.call(")
    assert "await consent('res:'" in res and res.index("await consent(") < res.index("rpc.call(")


def test_disable_totp_password_is_masked():
    """D-5"""
    settings = _js("views/settings.js")
    line = next(x for x in settings.splitlines() if "title: 'Disable two-factor'" in x)
    assert "type: 'password'" in line and "autocomplete: 'current-password'" in line
    assert "type, autocomplete" in _js("ui.js")


def test_global_shortcuts_do_not_query_untrusted_classes():
    """D-7: Ctrl+K / Esc / ? track the app's own dialogs by reference."""
    app = _js("app.js")
    for sel in (".palette", ".menu", ".shortcuts"):
        assert f"document.querySelector('{sel}')" not in app, sel
    assert "isMenuOpen()" in app and "paletteModal" in app and "shortcutsModal" in app


def test_signout_clears_client_state_and_sw_ignores_query():
    """D-8: sign-out clears local/session storage and the SW caches; the shell is cached under its path."""
    app = _js("app.js")
    logout = app.split("async function logout()", 1)[1].split("\n}", 1)[0]
    assert "await clearClientState();" in logout
    clear = app.split("async function clearClientState()", 1)[1].split("\n}", 1)[0]
    assert "localStorage.removeItem" in clear and "sessionStorage.clear()" in clear and "caches.delete" in clear
    sw = (JS.parent / "sw.js").read_text(encoding="utf-8")
    assert "const VERSION = 'gw-shell-v20';" in sw
    assert "c.put(key, copy)" in sw and "url.pathname === '/index.html' ? '/' : url.pathname" in sw


def test_asks_name_the_requesting_extension():
    """D-10: permission and elicitation cards say which extension/tool is asking."""
    asks = _js("asks.js")
    assert "export function askSource" in asks
    card = asks.split("export function askCard", 1)[1].split("\nexport function", 1)[0]
    assert card.count("sourceLine(ask)") >= 2
    assert "sourceLine(ask), elicitationWarning(ask)" in asks.split("export function openElicitationModal", 1)[1]


def test_versions_agree():
    root = Path(goose_web.__file__).parent.parent
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{goose_web.__version__}"' in pyproject
