# tests/test_logout.py
from client import register, login, send_msg, logout
import uuid

def test_logout_invalidates_session():
    print("=== test_logout_invalidates_session: start ===")
    u, p = f"tlogout_{uuid.uuid4().hex[:8]}", "pw"
    print("creating user:", u)
    resp_reg = register(u, p)
    print("register returned:", resp_reg)

    r = login(u, p); print("login returned:", r);                      assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)

    resp_send1 = send_msg(sid, "uno")
    print("first send_msg returned:", resp_send1)
    assert resp_send1["status"] == "ok"

    resp_logout = logout(sid)
    print("logout returned:", resp_logout)
    assert resp_logout["status"] == "ok"

    # volver a usar el mismo session_id debe fallar
    bad = send_msg(sid, "dos")
    print("second send_msg (should fail) returned:", bad)
    assert bad.get("status") == "error" and bad.get("reason") in ("invalid_session",), bad
    print("=== test_logout_invalidates_session passed ===")

if __name__ == "__main__":
    test_logout_invalidates_session()
    