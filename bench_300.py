# bench_300.py
import time, concurrent.futures as cf
from client import register, login, send_msg, logout

def flow(i):
    try:
        # 🔧 escalonado para evitar tormenta de handshakes
        # time.sleep(0.02 * i)  # 20 ms por hilo
        u, p = f"user{i}", "pw"
        register(u, p)
        r = login(u, p)
        if r.get("status") != "ok":
            print(f"[{i}] login fallo: {r}")
            return False
        sid = r["session_id"]
        ok = send_msg(sid, f"hello {i}")
        if ok.get("status") != "ok":
            print(f"[{i}] msg fallo: {ok}")
            return False
        logout(sid)
        return True
    except Exception as e:
        print(f"[{i}] EXCEPCIÓN: {e.__class__.__name__}: {e}")
        return False

if __name__ == "__main__":
    N = 300
    with cf.ThreadPoolExecutor(max_workers=N) as ex:
        results = list(ex.map(flow, range(N)))
    print("OK:", sum(results), "of", N)
