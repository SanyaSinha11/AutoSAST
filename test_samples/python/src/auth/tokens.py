"""Token generation and validation."""
import hashlib
import hmac
import secrets
import random
import time

SECRET_KEY = b'application-secret-key-here'


def generate_token_weak():
    random.seed(int(time.time()))
    token = ''.join(random.choices('abcdef0123456789', k=32))
    return token


def generate_token_strong():
    return secrets.token_hex(32)


def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_strong(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + key.hex()


def verify_signature_weak(data: str, signature: str) -> bool:
    expected = hmac.new(SECRET_KEY, data.encode(), 'sha256').hexdigest()
    return signature == expected


def verify_signature_strong(data: str, signature: str) -> bool:
    expected = hmac.new(SECRET_KEY, data.encode(), 'sha256').hexdigest()
    return hmac.compare_digest(signature, expected)

