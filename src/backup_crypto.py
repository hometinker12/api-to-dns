"""Password-based outer encryption for configuration backup archives."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

BACKUP_FORMAT = "api-to-dns-backup"
BACKUP_VERSION = 1
BACKUP_KDF = "pbkdf2_sha256"
DEFAULT_PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
# Cap attacker-controlled iteration counts from imported archives (DoS).
MAX_PBKDF2_ITERATIONS = 1_200_000


def _validated_iterations(iterations: int) -> int:
    value = int(iterations)
    if value < MIN_PBKDF2_ITERATIONS:
        raise ValueError("PBKDF2 iteration count is too low.")
    if value > MAX_PBKDF2_ITERATIONS:
        raise ValueError("PBKDF2 iteration count is too high.")
    return value


def derive_backup_fernet(password: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> Fernet:
    """Derive a Fernet key from a backup password via PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Backup password is required.")
    iterations = _validated_iterations(iterations)
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_payload(
    payload_json: bytes, password: str, *, iterations: int = DEFAULT_PBKDF2_ITERATIONS
) -> dict[str, Any]:
    salt = os.urandom(16)
    fernet = derive_backup_fernet(password, salt, iterations)
    token = fernet.encrypt(payload_json)
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "encrypted": True,
        "kdf": BACKUP_KDF,
        "iterations": int(iterations),
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": base64.b64encode(token).decode("ascii"),
    }


def decrypt_envelope(envelope: dict[str, Any], password: str) -> bytes:
    if envelope.get("format") != BACKUP_FORMAT:
        raise ValueError("Unrecognized backup format.")
    if not envelope.get("encrypted"):
        raise ValueError("Envelope is not encrypted.")
    if (envelope.get("kdf") or "") != BACKUP_KDF:
        raise ValueError("Unsupported backup key derivation.")
    salt = base64.b64decode(envelope["salt"])
    try:
        iterations = _validated_iterations(int(envelope.get("iterations") or DEFAULT_PBKDF2_ITERATIONS))
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid PBKDF2 iteration count.") from exc
    token = base64.b64decode(envelope["ciphertext"])
    fernet = derive_backup_fernet(password, salt, iterations)
    try:
        return fernet.decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Incorrect backup password or corrupt archive.") from exc
