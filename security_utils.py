# security_utils.py  (versión thread-safe para carga alta)
import os, hmac, hashlib, binascii, time, sqlite3, uuid, threading
from typing import Tuple, Optional

DB_PATH = "pai1.db"
_local = threading.local()
_write_lock = threading.Lock()  # serializa INSERT/UPDATE/DELETE

def _conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(
            DB_PATH,
            timeout=60,
            check_same_thread=False,
            isolation_level=None  # autocommit (usaremos "with conn:" para transacciones cortas)
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return conn

def init_db(path: str = "pai1.db"):
    global DB_PATH
    DB_PATH = path
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          username   TEXT PRIMARY KEY,
          salt       TEXT NOT NULL,
          pwd_hash   TEXT NOT NULL,
          failed     INTEGER DEFAULT 0,
          lock_until INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions(
          session_id TEXT PRIMARY KEY,
          username   TEXT NOT NULL,
          expires    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages(
          id        INTEGER PRIMARY KEY AUTOINCREMENT,
          username  TEXT NOT NULL,
          content   TEXT NOT NULL,
          ts        INTEGER NOT NULL,
          msg_mac   TEXT NOT NULL
        );
        """)
        for u, p in [("alice","password123"), ("bob","hunter2"), ("carla","mypwd")]:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone() is None:
                salt = gen_salt(); ph = pbkdf2_hash(p, salt)
                conn.execute("INSERT INTO users(username, salt, pwd_hash) VALUES (?,?,?)", (u, salt, ph))
    conn.close()
    return None  # ¡no devolvemos conexión compartida!

# --- Passwords ---
def gen_salt(n=16) -> str:
    return binascii.hexlify(os.urandom(n)).decode()

def pbkdf2_hash(password: str, salt: str, iterations=200_000) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return binascii.hexlify(dk).decode()

def verify_pwd(password: str, salt: str, pwd_hash: str) -> bool:
    if salt is None or pwd_hash is None:
        return False
    cand = pbkdf2_hash(password, salt)
    return hmac.compare_digest(cand, pwd_hash)

# --- Users ---
def save_user(db_ignored, username: str, salt: str, pwd_hash: str):
    with _write_lock, _conn() as c:
        c.execute("INSERT INTO users(username, salt, pwd_hash) VALUES (?,?,?)", (username, salt, pwd_hash))

def get_user(db_ignored, username: str) -> Optional[Tuple]:
    cur = _conn().execute("SELECT username, salt, pwd_hash, failed, lock_until FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    return (row["username"], row["salt"], row["pwd_hash"], row["failed"], row["lock_until"]) if row else None

def set_failed(db_ignored, username: str, failed: int, lock_until: int):
    with _write_lock, _conn() as c:
        c.execute("UPDATE users SET failed=?, lock_until=? WHERE username=?", (failed, lock_until, username))

# --- Sessions ---
def create_session(db_ignored, username: str, ttl: int = 3600):
    sid = str(uuid.uuid4()); exp = int(time.time()) + int(ttl)
    with _write_lock, _conn() as c:
        c.execute("INSERT INTO sessions(session_id, username, expires) VALUES (?,?,?)", (sid, username, exp))
    return sid, exp

def get_session(db_ignored, session_id: str) -> Optional[Tuple]:
    cur = _conn().execute("SELECT session_id, username, expires FROM sessions WHERE session_id=?", (session_id,))
    row = cur.fetchone()
    return (row["session_id"], row["username"], row["expires"]) if row else None

def delete_session(db_ignored, session_id: str):
    with _write_lock, _conn() as c:
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))

# --- Messages ---
MASTER_KEY = b'server-internal-mac-key-rotate-in-real-deploys'

def persist_message(db_ignored, username: str, content: str):
    ts = int(time.time())
    body = f"{username}|{content}|{ts}"
    mac = hmac.new(MASTER_KEY, body.encode(), hashlib.sha256).hexdigest()
    with _write_lock, _conn() as c:
        cur = c.execute("INSERT INTO messages(username, content, ts, msg_mac) VALUES (?,?,?,?)",
                        (username, content, ts, mac))
    return cur.lastrowid, ts

def count_messages(db_ignored, username: str) -> int:
    row = _conn().execute("SELECT COUNT(*) AS n FROM messages WHERE username=?", (username,)).fetchone()
    return int(row["n"]) if row else 0
