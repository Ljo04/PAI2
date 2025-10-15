# tests/test_valid_msg.py
from client import register, login, send_msg, logout

def test_valid_msg_flow():
    print("=== test_valid_msg_flow: start ===")
    result_reg = register("alice", "password123")  # ya existe -> ok
    print("register returned:", result_reg)

    r = login("alice", "password123"); print("login returned:", r); assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)

    m = send_msg(sid, "Hola PAI-2"); print("send_msg returned:", m); assert m.get("status") == "ok", m

    out = logout(sid); print("logout returned:", out); assert out.get("status") == "ok", out
    print("=== test_valid_msg_flow passed ===")

if __name__ == "__main__":
    test_valid_msg_flow()
