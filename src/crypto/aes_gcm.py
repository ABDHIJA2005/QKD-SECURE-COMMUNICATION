"""AES-256-GCM encryption with a versioned self-contained binary format.

Encrypted data is encoded as ``MAGIC || NONCE || CIPHERTEXT_AND_TAG``:

* ``MAGIC``: four bytes, ``b\"QKD1\"`` (format and version identifier)
* ``NONCE``: a freshly generated 96-bit GCM nonce
* ``CIPHERTEXT_AND_TAG``: output produced by ``AESGCM.encrypt``

The raw AES key is never stored in this representation.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_256_KEY_LENGTH = 32
FORMAT_MAGIC = b"QKD1"
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt arbitrary bytes with AES-256-GCM and a fresh nonce."""
    _validate_key(key)
    _validate_bytes(plaintext, "plaintext")

    nonce = os.urandom(GCM_NONCE_LENGTH)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, FORMAT_MAGIC)
    return FORMAT_MAGIC + nonce + ciphertext_and_tag


def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Authenticate and decrypt data produced by :func:`encrypt`.

    ``AESGCM`` raises ``InvalidTag`` if the nonce, ciphertext, tag, or
    authenticated format marker has been modified. No plaintext is returned
    when that authentication check fails.
    """
    _validate_key(key)
    _validate_bytes(encrypted_data, "encrypted_data")

    minimum_length = len(FORMAT_MAGIC) + GCM_NONCE_LENGTH + GCM_TAG_LENGTH
    if len(encrypted_data) < minimum_length:
        raise ValueError("Encrypted data is too short to contain a GCM tag.")
    if encrypted_data[: len(FORMAT_MAGIC)] != FORMAT_MAGIC:
        raise ValueError("Unsupported encrypted data format.")

    nonce_start = len(FORMAT_MAGIC)
    nonce_end = nonce_start + GCM_NONCE_LENGTH
    nonce = encrypted_data[nonce_start:nonce_end]
    ciphertext_and_tag = encrypted_data[nonce_end:]
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, FORMAT_MAGIC)


def _validate_key(key: bytes) -> None:
    _validate_bytes(key, "key")
    if len(key) != AES_256_KEY_LENGTH:
        raise ValueError("AES-256-GCM requires an exactly 32-byte key.")


def _validate_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes.")
