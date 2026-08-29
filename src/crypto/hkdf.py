"""HKDF derivation of application AES keys from accepted BB84 key material."""

from collections.abc import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.security import SecurityDecision


AES_256_KEY_LENGTH = 32
HKDF_INFO = b"QKD-Secure-Communication/AES-256-GCM/v1"


def derive_aes256_key(
    sifted_bits: Sequence[int], security_decision: SecurityDecision
) -> bytes:
    """Derive a 256-bit AES key from BB84 bits accepted by the security check.

    ``HKDF_INFO`` binds this output to version 1 of this application's
    AES-256-GCM use case. This function uses HKDF-SHA256, not a password-based
    KDF, and never logs or stores the derived key.

    Raises:
        TypeError: If inputs have the wrong type.
        ValueError: If the key material is empty or invalid, or the BB84
            security decision rejected it.
    """
    if not isinstance(security_decision, SecurityDecision):
        raise TypeError("security_decision must be a SecurityDecision.")
    if not security_decision.accepted:
        raise ValueError("Rejected BB84 key material cannot derive an application key.")

    input_key_material = _encode_bits(sifted_bits)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_LENGTH,
        salt=None,
        info=HKDF_INFO,
    ).derive(input_key_material)


def _encode_bits(bits: Sequence[int]) -> bytes:
    """Encode BB84 bits unambiguously, including their original bit length."""
    if isinstance(bits, (str, bytes, bytearray)) or not isinstance(bits, Sequence):
        raise TypeError("sifted_bits must be a non-empty sequence of binary integers.")
    if not bits:
        raise ValueError("BB84 key material must not be empty.")
    if any(
        isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1)
        for bit in bits
    ):
        raise ValueError("BB84 key material must contain only integer bits 0 or 1.")

    packed = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        packed[index // 8] |= bit << (7 - (index % 8))

    return len(bits).to_bytes(4, "big") + bytes(packed)
