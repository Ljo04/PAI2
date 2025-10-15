# tests/test_tamper.py
from client import register, login, send_msg
from security_utils import MASTER_KEY
import sqlite3, hmac, hashlib, uuid

DB = "pai1.db"

def _compute_mac(username, content, ts):
    body = f"{username}|{content}|{ts}"
    return hmac.new(MASTER_KEY, body.encode(), hashlib.sha256).hexdigest()

def test_db_tamper_detected_by_hmac():
    u, p = f"ttamp_{uuid.uuid4().hex[:8]}", "pw"
    register(u, p)
    print("=== test_db_tamper_detected_by_hmac: start ===")
    r = login(u, p); print("login returned:", r); assert r.get("status") == "ok", r
    sid = r["session_id"]
    print("session_id:", sid)
    ok = send_msg(sid, "original"); print("send_msg returned:", ok); assert ok.get("status") == "ok", ok

    # leemos el último mensaje del usuario
    with sqlite3.connect(DB) as db:
        cur = db.execute("SELECT id, content, ts, msg_mac FROM messages WHERE username=? ORDER BY id DESC LIMIT 1", (u,))
        row = cur.fetchone()
        assert row, "no hay mensajes"
        mid, content, ts, mac = row
        print("db row before tamper:", {"id": mid, "content": content, "ts": ts, "mac": mac})
        # MAC correcto inicialmente
        computed = _compute_mac(u, content, ts)
        print("computed mac before tamper:", computed)
        assert mac == computed

        # manipulamos la BD
        db.execute("UPDATE messages SET content=? WHERE id=?", ("EVIL", mid))
        db.commit()

        # vuelve a leer y verifica que el MAC ya no coincide
        cur = db.execute("SELECT content, ts, msg_mac FROM messages WHERE id=?", (mid,))
        content2, ts2, mac2 = cur.fetchone()
        print("db row after tamper:", {"id": mid, "content": content2, "ts": ts2, "mac": mac2})
        computed2 = _compute_mac(u, content2, ts2)
        print("computed mac after tamper:", computed2)
        assert mac2 != computed2, "la manipulación debería romper el MAC"
    print("=== test_db_tamper_detected_by_hmac passed ===")

if __name__ == "__main__":
    test_db_tamper_detected_by_hmac()