# tests/test_expiry.py
from client import register, login, send_msg
import sqlite3, time, uuid

DB = "pai1.db"

def test_session_expiry_enforced():
    print("=== test_session_expiry_enforced: start ===")
    u, p = f"texp_{uuid.uuid4().hex[:8]}", "pw"
    print("creating user:", u)
    resp_reg = register(u, p)
    print("register returned:", resp_reg)

    r = login(u, p); print("login returned:", r); assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)

    # forzamos caducidad en BD
    with sqlite3.connect(DB) as db:
        db.execute("UPDATE sessions SET expires=? WHERE session_id= ?", (int(time.time())-1, sid))
        db.commit()
    print("forced expiry in DB for session", sid)

    bad = send_msg(sid, "esto no debería pasar")
    print("send_msg with expired session returned:", bad)
    assert bad.get("status") == "error" and bad.get("reason") == "session_expired", bad
    print("=== test_session_expiry_enforced passed ===")

if __name__ == "__main__":
    test_session_expiry_enforced()

