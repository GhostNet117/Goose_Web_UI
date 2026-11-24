"""Personal goose hints are on for NEW teams (released with specs 037/038).

Members could already write personal hints (Settings > Goose hints) - only when their team's switch "Members may add
personal hints" (`hints_edit`) was on, and a new team started with it off. A team created from now on stores it on
(policy.NEW_TEAM_POLICY): Admin > Teams > New team, `goose-web init`'s Everyone and `native-hints enable --team`.
Teams that exist keep what they have (nothing is migrated), a person without a team keeps the least-privilege base
(no personal hints), and the team's hints stay last and final in what Goose loads."""
import json

from goose_web import policy as pol
from goose_web.profiles import HINTS_HEADER

from test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)


def test_a_new_team_lets_its_members_add_personal_hints(env):
    s, db, pr, c = env
    admin = user(db, "root", role="admin")
    old = team(db, "Before", ANYCHAT)                    # a team stored by an earlier version: not touched
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        r = tc.post("/api/admin/teams", json={"name": "New", "policy": ANYCHAT}, headers=h)
        assert r.status_code == 200, r.text
        tid = r.json()["id"]
        assert db.one("SELECT policy FROM teams WHERE id=?", (tid,))["policy"]["hints_edit"] is True
        assert r.json()["team"]["policy"]["hints_edit"] is True
        assert any("Members may add personal hints" in w["text"] for w in r.json()["team"]["warnings"])
        # an administrator who creates a team with the switch off gets it off
        r = tc.post("/api/admin/teams", json={"name": "Strict", "policy": {**ANYCHAT, "hints_edit": False}}, headers=h)
        assert db.one("SELECT policy FROM teams WHERE id=?", (r.json()["id"],))["policy"]["hints_edit"] is False
        # and can switch it off later like any switch
        assert tc.patch(f"/api/admin/teams/{tid}", json={"policy": {**ANYCHAT, "hints_edit": False}},
                        headers=h).status_code == 200
        assert db.one("SELECT policy FROM teams WHERE id=?", (tid,))["policy"]["hints_edit"] is False
        assert tc.patch(f"/api/admin/teams/{tid}", json={"policy": {**ANYCHAT, "hints_edit": True}},
                        headers=h).status_code == 200
    assert "hints_edit" not in db.one("SELECT policy FROM teams WHERE id=?", (old,))["policy"]

    ann = user(db, "ann")
    db.set_user_team(ann["id"], tid)
    assert pol.effective_policy(ann, db.user_teams(ann["id"]))["hints_edit"] is True
    with client_for(c) as tc:
        h = sign_in(tc, c, ann)
        got = tc.get("/api/me/hints").json()
        assert got["editable"] is True
        assert tc.put("/api/me/hints", json={"personal": "- PERSONAL: answer briefly"}, headers=h).status_code == 200
    doc = db.execute("INSERT INTO hints_docs(name, content, updated_at) VALUES('rules', 'TEAM RULE', 0)")
    db.execute("INSERT INTO team_hints VALUES(?,?)", (tid, doc))
    text = pr.compose_hints(db.user_by_id(ann["id"]))
    # personal first, the team's hints last and final
    assert text.startswith(HINTS_HEADER) and text.index("PERSONAL: answer briefly") < text.index("TEAM RULE")
    assert "Team: New (final" in text and not pr.hint_sections(db.user_by_id(ann["id"]))["personalDropped"]

    # the stored team of an earlier version keeps "off"; somebody without a team keeps the base
    bob = user(db, "bob", personal_hints="- mine")
    db.set_user_team(bob["id"], old)
    assert pol.effective_policy(bob, db.user_teams(bob["id"]))["hints_edit"] is False
    assert pr.hint_sections(db.user_by_id(bob["id"]))["personalDropped"] is True
    nobody = user(db, "nobody")
    assert pol.effective_policy(nobody, [])["hints_edit"] is False and pol.DEFAULT_POLICY["hints_edit"] is False
    assert pol.NEW_TEAM_POLICY == {"hints_edit": True}


def test_init_and_native_hints_create_teams_with_personal_hints(tmp_path):
    from goose_web.__main__ import main
    from goose_web.db import Database
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"paths:\n  profiles_root: \"{tmp_path.as_posix()}\"\n", encoding="utf-8")
    native = tmp_path / "Goose_appdata"
    (native / "config").mkdir(parents=True)
    assert main(["--config", str(cfg), "init", "--admin", "boss", "--password", "Long-enough-pw-1!",
                 "--native-root", str(native)]) == 0
    assert main(["--config", str(cfg), "native-hints", "enable", "boss", "--team", "Admins"]) == 0
    db = Database(tmp_path / "_system" / "goose-web.db")
    try:
        got = {t["name"]: t["policy"] for t in db.query("SELECT name, policy FROM teams")}
        assert got == {"Everyone": {"hints_edit": True}, "Admins": {"hints_edit": True}}
        assert json.dumps(got["Everyone"]) == json.dumps(pol.NEW_TEAM_POLICY)
    finally:
        db.close()
