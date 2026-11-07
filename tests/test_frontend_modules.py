"""Static checks of the browser app's ES modules (no browser or Node needed).

Every relative `import { a, b } from './x.js'` must point at an existing file that exports each imported
name. A missing export only fails at runtime in the browser, which no other test would notice (spec 008
moved `pillSelect` from views/chat.js into chatoptions.js)."""
import re
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


def test_versions_agree():
    root = Path(goose_web.__file__).parent.parent
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{goose_web.__version__}"' in pyproject
