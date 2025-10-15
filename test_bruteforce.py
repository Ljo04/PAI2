# tests/test_bruteforce.py
from client import register, login
import uuid

def test_bruteforce_lockout_then_correct_is_locked():
    print("=== test_bruteforce_lockout_then_correct_is_locked: start ===")
    u, good = f"tbf_{uuid.uuid4().hex[:8]}", "goodpw"
    print("creating user:", u)
    resp_reg = register(u, good)
    print("register returned:", resp_reg)

    # 5 intentos con contraseña mala (umbral de bloqueo = 5)
    for i in range(5):
        r = login(u, "wrong")
        print(f"attempt {i+1} with wrong password returned:", r)

    # debería quedar bloqueado
    print("after wrong attempts, last response:", r)
    assert r.get("status") == "error" and r.get("reason") in ("locked", "invalid_credentials")

    # Incluso con la correcta, debe seguir bloqueado (sin esperar 5 min)
    r2 = login(u, good)
    print("attempt with correct password returned:", r2)
    assert r2.get("status") == "error" and r2.get("reason") in ("locked",), r2
    print("=== test_bruteforce_lockout_then_correct_is_locked passed ===")

if __name__ == "__main__":
    test_bruteforce_lockout_then_correct_is_locked()
