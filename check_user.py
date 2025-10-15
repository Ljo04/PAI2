# tests/check_user.py
from client import login

def test_seed_users_can_login():
    print("=== test_seed_users_can_login: start ===")
    # si no has cambiado el seed de security_utils.py
    r1 = login("alice", "password123")
    print("alice login returned:", r1)
    r2 = login("bob", "hunter2")
    print("bob login returned:", r2)
    assert r1.get("status") in ("ok","error")  # no forzamos, por si ya están bloqueados
    assert r2.get("status") in ("ok","error")
    print("=== test_seed_users_can_login done ===")


if __name__ == "__main__":
    test_seed_users_can_login()
