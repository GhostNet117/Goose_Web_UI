"""CI only; run by selftest-as-service.ps1.

What a gateway measures at its start (goose_web.sandbox.selftest): does a process in an AppContainer start from
here? "Here" is whoever runs this file - the script runs it once from a scheduled task, as a local account that is
not an administrator and never signs in, which is how a gateway started at boot runs. One JSON object is written
to the path given as the first argument."""
import json
import os
import sys
import traceback

out: dict = {"ok": False}
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from goose_web import relay
    from goose_web import sandbox as sb
    res = sb.selftest(relay.python_for_container()[0])
    out = {**res, "text": sb.selftest_text(res)[1], "user": os.environ.get("USERNAME", "")}
except BaseException:       # whatever it is, the caller must see it: nobody looks at this process
    out["error"] = traceback.format_exc()[-1500:]
with open(sys.argv[1] + ".tmp", "w", encoding="utf-8") as f:
    json.dump(out, f)
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
