"""Tests for HKDF key derivation and AES-256-GCM encryption."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from src.bb84 import BB84Simulation
from src.crypto import decrypt, derive_aes256_key, encrypt
from src.crypto.aes_gcm import FORMAT_MAGIC
from src.security import assess_key_security


ACCEPTED_DECISION = assess_key_security(0.0)
KEY_MATERIAL = (0, 1, 1, 0, 1, 0, 0, 1, 1)


def test_same_accepted_bb84_material_derives_the_same_key() -> None:
    first = derive_aes256_key(KEY_MATERIAL, ACCEPTED_DECISION)
    second = derive_aes256_key(KEY_MATERIAL, ACCEPTED_DECISION)

    assert first == second


def test_derived_key_is_256_bits_and_not_a_hard_coded_constant() -> None:
    first = derive_aes256_key(KEY_MATERIAL, ACCEPTED_DECISION)
    second = derive_aes256_key(KEY_MATERIAL + (0,), ACCEPTED_DECISION)

    assert len(first) == 32
    assert first != second


def test_invalid_or_empty_bb84_key_material_is_rejected() -> None:
    with pytest.raises(ValueError):
        derive_aes256_key((), ACCEPTED_DECISION)
    with pytest.raises(ValueError):
        derive_aes256_key((0, 2, 1), ACCEPTED_DECISION)
    with pytest.raises(TypeError):
        derive_aes256_key(b"0101", ACCEPTED_DECISION)


def test_rejected_bb84_decision_cannot_derive_an_application_key() -> None:
    rejected = assess_key_security(0.12)

    with pytest.raises(ValueError, match="Rejected BB84"):
        derive_aes256_key(KEY_MATERIAL, rejected)


def test_aes_gcm_round_trip() -> None:
    key = os.urandom(32)
    plaintext = b"authenticated QKD application payload"

    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_aes_gcm_encrypts_empty_plaintext() -> None:
    key = os.urandom(32)

    assert decrypt(encrypt(b"", key), key) == b""


def test_aes_gcm_round_trip_supports_arbitrary_binary_data() -> None:
    key = os.urandom(32)
    plaintext = bytes(range(256))

    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_aes_gcm_round_trip_supports_large_data() -> None:
    key = os.urandom(32)
    plaintext = bytes(range(256)) * 4_096

    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_each_encryption_uses_a_fresh_nonce() -> None:
    key = os.urandom(32)

    first = encrypt(b"same payload", key)
    second = encrypt(b"same payload", key)

    assert first != second
    assert first[len(FORMAT_MAGIC) : len(FORMAT_MAGIC) + 12] != second[
        len(FORMAT_MAGIC) : len(FORMAT_MAGIC) + 12
    ]


def test_modified_ciphertext_fails_authentication() -> None:
    key = os.urandom(32)
    encrypted = bytearray(encrypt(b"protected", key))
    encrypted[-1] ^= 1

    with pytest.raises(InvalidTag):
        decrypt(bytes(encrypted), key)


def test_modified_nonce_fails_authentication() -> None:
    key = os.urandom(32)
    encrypted = bytearray(encrypt(b"protected", key))
    encrypted[len(FORMAT_MAGIC)] ^= 1

    with pytest.raises(InvalidTag):
        decrypt(bytes(encrypted), key)


def test_wrong_aes_key_fails_authentication() -> None:
    encrypted = encrypt(b"protected", os.urandom(32))

    with pytest.raises(InvalidTag):
        decrypt(encrypted, os.urandom(32))


@pytest.mark.parametrize("invalid_data", [b"", b"QKD1", b"BAD1" + b"x" * 28])
def test_invalid_encrypted_data_is_rejected(invalid_data: bytes) -> None:
    with pytest.raises(ValueError):
        decrypt(invalid_data, os.urandom(32))


@pytest.mark.parametrize("invalid_key", [b"", b"x" * 31, b"x" * 33])
def test_aes_key_must_be_exactly_32_bytes(invalid_key: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt(b"data", invalid_key)


def test_accepted_bb84_result_derives_a_key_for_aes_round_trip() -> None:
    result = BB84Simulation().run(256)
    key = derive_aes256_key(
        result.sifted_key.alice_bits, result.metadata.security_decision
    )

    assert decrypt(encrypt(b"integration payload", key), key) == b"integration payload"


def test_rejected_bb84_result_cannot_derive_an_application_key() -> None:
    result = BB84Simulation(eve_enabled=True).run(4_000)

    assert result.metadata.security_decision.accepted is False
    with pytest.raises(ValueError, match="Rejected BB84"):
        derive_aes256_key(
            result.sifted_key.alice_bits, result.metadata.security_decision
        )
