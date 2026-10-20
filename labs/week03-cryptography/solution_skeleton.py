"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def verify_and_upgrade(stored_hash: str, pw: str) -> str | None:
    # FIX: rehash-on-login — legacy MD5 records (32 hex chars) get upgraded
    # to argon2id the moment the user logs in successfully.
    if len(stored_hash) == 32:
        if hashlib.md5(pw.encode()).hexdigest() != stored_hash:
            return None
        return store_password(pw)
    return stored_hash if verify_password(stored_hash, pw) else None

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)

if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    print("gcm:", encrypt_gcm(b"secret", key))
    print("Task 3 Sample Tokens:")
    for _ in range(5):
        print(reset_token())

    print("Task 6 rehash-on-login:")
    legacy = hashlib.md5(b"password123").hexdigest()
    new_hash = verify_and_upgrade(legacy, "password123")
    print("  legacy:", legacy)
    print("  upgraded:", new_hash)