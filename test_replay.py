# tests/test_replay.py
from client import register, login, send_msg, logout
import uuid

def test_cannot_reuse_session_after_logout():
    print("=== test_cannot_reuse_session_after_logout: start ===")
    u, p = f"trep_{uuid.uuid4().hex[:8]}", "pw"
    print("creating user:", u)
    resp_reg = register(u, p)
    print("register returned:", resp_reg)

    r = login(u, p); print("login returned:", r); assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)

    resp1 = send_msg(sid, "msg1")
    print("first send_msg returned:", resp1)
    assert resp1["status"] == "ok"

    resp_logout = logout(sid)
    print("logout returned:", resp_logout)
    assert resp_logout["status"] == "ok"

    # “replay” del mismo token de sesión
    res = send_msg(sid, "msg2")
    print("replay attempt returned:", res)
    assert res.get("status") == "error" and res.get("reason") in ("invalid_session",), res
    print("=== test_cannot_reuse_session_after_logout passed ===")

if __name__ == "__main__":
    test_cannot_reuse_session_after_logout()