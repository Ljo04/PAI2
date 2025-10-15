# client.py (PAI-2)
#!/usr/bin/env python3
import ssl, socket, json, sys

HOST = "127.0.0.1"
PORT = 9000
CONNECT_TIMEOUT = 10.0
RECV_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 60.0

def _recv_line(s):
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            return None, 'connection_closed'
        data += chunk
        if b'\n' in data:
            line, _ = data.split(b'\n', 1)
            try:
                return json.loads(line.decode()), None
            except Exception as e:
                return None, f'invalid_json_resp: {e}'

def _tls_context():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Validamos el certificado del servidor (usa server.crt generado por gen_cert.py)
    ctx.load_verify_locations("server.crt")
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx

def _send_recv(msg):
    ctx = _tls_context()
    with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as raw:
        raw.settimeout(HANDSHAKE_TIMEOUT)
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.settimeout(RECV_TIMEOUT)
            s.sendall((json.dumps(msg) + "\n").encode())
            resp, err = _recv_line(s)
            if err: return {"status":"error","reason":err}
            return resp

def register(username, password):
    return _send_recv({"type":"register","username":username,"password":password})

def login(username, password):
    return _send_recv({"type":"login","username":username,"password":password})

def send_msg(session_id, content):
    if not isinstance(content, str) or len(content) == 0:
        return {"status":"error","reason":"bad_message"}
    if len(content) > 144:
        return {"status":"error","reason":"msg_too_long"}
    return _send_recv({"type":"msg","session_id":session_id,"content":content})

def logout(session_id):
    return _send_recv({"type":"logout","session_id":session_id})

if __name__ == "__main__":
    # Uso rápido: python client.py login alice password123
    if len(sys.argv) < 2:
        print("Usage: client.py [register|login|msg|logout] ...")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "register" and len(sys.argv) >= 4:
        print(register(sys.argv[2], sys.argv[3]))
    elif cmd == "login" and len(sys.argv) >= 4:
        print(login(sys.argv[2], sys.argv[3]))
    elif cmd == "msg" and len(sys.argv) >= 4:
        print(send_msg(sys.argv[2], " ".join(sys.argv[3:])))
    elif cmd == "logout" and len(sys.argv) >= 3:
        print(logout(sys.argv[2]))
    else:
        print("unknown or malformed command")
