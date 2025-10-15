# tests/test_len_limit.py
from client import register, login, send_msg

def test_len_144():
    print("=== test_len_144: start ===")
    _ = register("bob", "hunter2")
    r = login("bob", "hunter2"); print("login returned:", r); assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)

    ok = send_msg(sid, "x"*144); print("send_msg 144 returned:", ok); assert ok.get("status") == "ok", ok
    bad = send_msg(sid, "x"*145); print("send_msg 145 returned:", bad); assert bad.get("status") == "error" and bad.get("reason")=="msg_too_long", bad
    print("=== test_len_144 passed ===")

if __name__ == "__main__":
    test_len_144()