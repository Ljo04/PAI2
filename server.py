# server_pai2.py
#!/usr/bin/env python3
import json, socket, ssl, threading, time
from security_utils import (
    init_db, save_user, get_user, verify_pwd,
    set_failed, create_session, get_session, delete_session,
    persist_message, count_messages, gen_salt, pbkdf2_hash
)

HOST, PORT = "127.0.0.1", 9000
LOCK_THRESHOLD = 5
LOCK_SECONDS = 5 * 60
SESSION_TTL = 3600

db = init_db()

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())

def handle_register(msg):
    u = msg.get("username","")
    p = msg.get("password","")
    if not u or not p:
        return {"status":"error","reason":"bad_request"}

    if get_user(db, u) is not None:
        return {"status":"error","reason":"user_exists"}

    salt = gen_salt()
    pwd_hash = pbkdf2_hash(p, salt)
    save_user(db, u, salt, pwd_hash)
    return {"status":"ok","msg":"user_registered"}

def handle_login(msg):
    u = msg.get("username","")
    p = msg.get("password","")
    row = get_user(db, u)
    if not row:
        return {"status":"error","reason":"invalid_credentials"}

    username, salt, pwd_hash, failed, lock_until = row
    now = int(time.time())
    if lock_until and lock_until > now:
        return {"status":"error","reason":"locked","until":lock_until}

    if not verify_pwd(p, salt, pwd_hash):
        failed = (failed or 0) + 1
        lu = now + LOCK_SECONDS if failed >= LOCK_THRESHOLD else 0
        set_failed(db, u, failed, lu)
        return {"status":"error","reason":"invalid_credentials" if not lu else "locked"}

    # éxito: resetear contador
    set_failed(db, u, 0, 0)
    sid, exp = create_session(db, u, ttl=SESSION_TTL)
    return {"status":"ok","session_id":sid,"expires":exp}

def handle_msg(msg):
    sid = msg.get("session_id")
    content = msg.get("content","")
    if not sid:
        return {"status":"error","reason":"invalid_session"}
    row = get_session(db, sid)
    if not row:
        return {"status":"error","reason":"invalid_session"}
    session_id, username, expires = row
    if int(time.time()) >= int(expires):
        return {"status":"error","reason":"session_expired"}

    if not isinstance(content, str):
        return {"status":"error","reason":"bad_message"}
    if len(content) > 144:   # PAI-2: límite 144 chars
        return {"status":"error","reason":"msg_too_long"}

    msg_id, ts = persist_message(db, username, content)
    total = count_messages(db, username)
    return {"status":"ok","message_id":msg_id,"ts":ts,"total_sent_by_user":total}

def handle_logout(msg):
    sid = msg.get("session_id")
    if sid:
        delete_session(db, sid)
    return {"status":"ok","msg":"logged_out"}

def handle_request(obj):
    t = obj.get("type")
    if t == "register": return handle_register(obj)
    if t == "login":    return handle_login(obj)
    if t == "msg":      return handle_msg(obj)
    if t == "logout":   return handle_logout(obj)
    return {"status":"error","reason":"unknown_command"}

def client_thread(conn):
    try:
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    req = json.loads(line.decode())
                except Exception:
                    send_json(conn, {"status":"error","reason":"invalid_json"})
                    continue
                resp = handle_request(req)
                send_json(conn, resp)
    finally:
        try: conn.shutdown(socket.SHUT_RDWR)
        except: pass
        conn.close()

def accept_thread(ctx, raw, addr):
    try:
        conn = ctx.wrap_socket(raw, server_side=True)  # handshake en hilo
        client_thread(conn)
    except Exception:
        try: raw.close()
        except: pass

def serve_forever():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

    with socket.create_server((HOST, PORT), reuse_port=False) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.listen(1024)  # backlog alto
        print(f"[PAI-2] TLS server listening on {HOST}:{PORT} (TLS 1.3)")
        while True:
            raw, addr = sock.accept()
            threading.Thread(target=accept_thread, args=(ctx, raw, addr), daemon=True).start()

if __name__ == "__main__":
    serve_forever()
