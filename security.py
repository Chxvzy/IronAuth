import hashlib, hmac, secrets

N, R, P = 2**14, 8, 1

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=N, r=R, p=P)
    return f"scrypt${N}${R}${P}${salt.hex()}${h.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(calc, bytes.fromhex(h))
    except (ValueError, TypeError):
        return False

def new_token() -> str:
    return secrets.token_urlsafe(32)

def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
