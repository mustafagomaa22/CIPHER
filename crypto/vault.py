"""
CIPHER — Vault Crypto Layer
Handles all encryption and decryption of data files using Blowfish CBC.
Every file on disk is encrypted — vault, cases, actors, audit log, notes, watchlist.
No plaintext data is ever written to disk.
"""

import os
import json
import secrets
import hashlib

from config import KEY_FILE
from crypto.blowfish import encrypt as bf_encrypt, decrypt as bf_decrypt


# ── Key Management ─────────────────────────────────────────────────────────────

def get_vault_key() -> bytes:
    """
    Load the current Blowfish encryption key from disk.
    If no key exists yet, generate a fresh 256-bit key and save it.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()

    # First run — generate a new random 256-bit key
    key = secrets.token_bytes(32)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


def rotate_key(new_key: bytes, file_paths: list):
    """
    Re-encrypt all given files with a new Blowfish key.
    Reads each file with the old key, writes it back with the new one.
    Called during key rotation — old key is discarded after this.
    """
    old_key = get_vault_key()

    for path in file_paths:
        if not os.path.exists(path):
            continue
        data = _decrypt_file(path, old_key)
        _encrypt_file(data, path, new_key)

    # Overwrite the key file with the new key
    with open(KEY_FILE, 'wb') as f:
        f.write(new_key)


# ── File-level Encrypt / Decrypt ───────────────────────────────────────────────

def _encrypt_file(data: list | dict, path: str, key: bytes = None):
    """Serialize data to JSON and encrypt it to the given file path."""
    if key is None:
        key = get_vault_key()
    plaintext  = json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8')
    ciphertext = bf_encrypt(key, plaintext)
    with open(path, 'wb') as f:
        f.write(ciphertext)


def _decrypt_file(path: str, key: bytes = None) -> list | dict:
    """Decrypt a file and deserialize its JSON contents."""
    if not os.path.exists(path):
        return []
    with open(path, 'rb') as f:
        ciphertext = f.read()
    if not ciphertext:
        return []
    if key is None:
        key = get_vault_key()
    try:
        plaintext = bf_decrypt(key, ciphertext)
        return json.loads(plaintext.decode('utf-8'))
    except Exception:
        return []


# ── Public API ─────────────────────────────────────────────────────────────────

def save(data: list | dict, path: str):
    """Encrypt and save data to a file."""
    _encrypt_file(data, path)


def load(path: str) -> list:
    """Load and decrypt a list from a file."""
    result = _decrypt_file(path)
    return result if isinstance(result, list) else []


def load_dict(path: str) -> dict:
    """Load and decrypt a dict from a file."""
    result = _decrypt_file(path)
    return result if isinstance(result, dict) else {}


# ── Password Hashing ───────────────────────────────────────────────────────────

def hash_password(password: str, salt: str) -> str:
    """
    Hash a password using SHA-256 with a random salt.
    We never store the password itself — only the salt and hash.
    """
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """Check a password against a stored hash."""
    return hash_password(password, salt) == stored_hash


# ── Threat Scoring ─────────────────────────────────────────────────────────────

def calculate_score(entry: dict) -> int:
    """
    Calculate a 0–100 threat score for an IOC based on:
    - Severity level
    - IOC type
    - TLP classification
    - Active status bonus
    - Dangerous tag detection
    - MITRE technique count

    Higher score = more dangerous / higher priority.
    """
    from config import SEVERITY_WEIGHTS, TYPE_WEIGHTS, TLP_WEIGHTS, DANGER_TAGS

    score = 0
    score += SEVERITY_WEIGHTS.get(entry.get('severity', 'low'), 0)
    score += TYPE_WEIGHTS.get(entry.get('type', 'other'), 5)
    score += TLP_WEIGHTS.get(entry.get('tlp', 'WHITE'), 0)

    # Active IOCs are more urgent
    if entry.get('status') == 'active':
        score += 12

    # Dangerous tags push the score up (capped at 10)
    dangerous = sum(
        3 for tag in entry.get('tags', [])
        if tag.lower() in DANGER_TAGS
    )
    score += min(10, dangerous)

    # More MITRE techniques = more sophisticated threat (capped at 5)
    score += min(5, len(entry.get('mitre_techniques', [])))

    return min(100, score)
