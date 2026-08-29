"""Tests for the BB84-gated file encryption pipeline."""

from dataclasses import asdict
import os
from pathlib import Path

import pytest

from src.crypto import derive_aes256_key, encrypt
from src.file_crypto import FILE_FORMAT_MAGIC, FileDecryptionService, FileEncryptionService
from src.qrng import RandomBitSource
from src.security import assess_key_security


class AllZeroBitSource(RandomBitSource):
    """Predictable test double that makes every no-Eve basis rectilinear."""

    def generate_bits(self, n: int) -> list[int]:
        return [0] * n


def _accepted_service() -> FileEncryptionService:
    return FileEncryptionService(AllZeroBitSource(), bb84_bit_count=128)


def _accepted_key() -> bytes:
    return derive_aes256_key((0,) * 128, assess_key_security(0.0))


def _encrypt_file(tmp_path: Path, filename: str, content: bytes):
    input_path = tmp_path / filename
    input_path.write_bytes(content)
    result = _accepted_service().encrypt_file(input_path)
    assert result.success is True
    assert result.output_path is not None
    return input_path, result


def _decrypt_to_new_directory(tmp_path: Path, encrypted_path: Path):
    destination = tmp_path / "decrypted"
    destination.mkdir()
    return FileDecryptionService().decrypt_file(
        encrypted_path, _accepted_key(), output_directory=destination
    )


def test_text_file_end_to_end_pipeline_restores_original_bytes(tmp_path: Path) -> None:
    content = b"QKD-secured report\nwith multiple lines.\n"
    input_path, encryption = _encrypt_file(tmp_path, "report.txt", content)

    decryption = _decrypt_to_new_directory(tmp_path, encryption.output_path)

    assert encryption.output_filename == "report.txt.enc"
    assert decryption.success is True
    assert decryption.output_path is not None
    assert decryption.output_path.read_bytes() == content
    assert input_path.read_bytes() == content


def test_binary_file_encryption_and_decryption(tmp_path: Path) -> None:
    content = bytes(range(256)) * 3
    _, encryption = _encrypt_file(tmp_path, "payload.bin", content)

    decryption = _decrypt_to_new_directory(tmp_path, encryption.output_path)

    assert decryption.output_path is not None
    assert decryption.output_path.read_bytes() == content


def test_empty_file_encryption_and_decryption(tmp_path: Path) -> None:
    _, encryption = _encrypt_file(tmp_path, "empty.dat", b"")

    decryption = _decrypt_to_new_directory(tmp_path, encryption.output_path)

    assert decryption.success is True
    assert decryption.output_file_size == 0


def test_larger_file_encryption_and_decryption(tmp_path: Path) -> None:
    content = os.urandom(1_048_576)
    _, encryption = _encrypt_file(tmp_path, "large.bin", content)

    decryption = _decrypt_to_new_directory(tmp_path, encryption.output_path)

    assert decryption.output_path is not None
    assert decryption.output_path.read_bytes() == content


def test_original_file_is_untouched_and_enc_file_is_created(tmp_path: Path) -> None:
    content = b"original content"
    input_path, encryption = _encrypt_file(tmp_path, "original.txt", content)

    assert input_path.read_bytes() == content
    assert encryption.output_path == tmp_path / "original.txt.enc"
    assert encryption.output_path.exists()
    assert encryption.output_file_size > len(content)


def test_incorrect_aes_key_fails_without_writing_plaintext(tmp_path: Path) -> None:
    _, encryption = _encrypt_file(tmp_path, "secret.txt", b"secret")
    destination = tmp_path / "wrong-key-output"
    destination.mkdir()

    result = FileDecryptionService().decrypt_file(
        encryption.output_path, os.urandom(32), output_directory=destination
    )

    assert result.success is False
    assert result.authentication_verified is False
    assert list(destination.iterdir()) == []


def test_tampered_encrypted_file_fails_authentication(tmp_path: Path) -> None:
    _, encryption = _encrypt_file(tmp_path, "secret.txt", b"secret")
    tampered_path = tmp_path / "tampered.enc"
    tampered = bytearray(encryption.output_path.read_bytes())
    tampered[-1] ^= 1
    tampered_path.write_bytes(tampered)

    result = _decrypt_to_new_directory(tmp_path, tampered_path)

    assert result.success is False
    assert result.authentication_verified is False


def test_invalid_encrypted_file_is_rejected(tmp_path: Path) -> None:
    invalid_path = tmp_path / "invalid.enc"
    invalid_path.write_bytes(b"not an encrypted file")
    destination = tmp_path / "invalid-output"
    destination.mkdir()

    result = FileDecryptionService().decrypt_file(
        invalid_path, _accepted_key(), output_directory=destination
    )

    assert result.success is False
    assert result.decryption_completed is False
    assert list(destination.iterdir()) == []


def test_path_traversal_filename_metadata_is_rejected(tmp_path: Path) -> None:
    key = _accepted_key()
    unsafe_name = b"../../important_file.txt"
    malicious_plaintext = len(unsafe_name).to_bytes(2, "big") + unsafe_name + b"data"
    malicious_path = tmp_path / "malicious.enc"
    malicious_path.write_bytes(FILE_FORMAT_MAGIC + encrypt(malicious_plaintext, key))
    destination = tmp_path / "safe-output"
    destination.mkdir()

    result = FileDecryptionService().decrypt_file(
        malicious_path, key, output_directory=destination
    )

    assert result.success is False
    assert result.authentication_verified is True
    assert list(destination.iterdir()) == []


def test_existing_output_files_are_not_silently_overwritten(tmp_path: Path) -> None:
    input_path, encryption = _encrypt_file(tmp_path, "report.txt", b"first")

    with pytest.raises(FileExistsError):
        _accepted_service().encrypt_file(input_path)

    destination = tmp_path / "decrypted"
    destination.mkdir()
    FileDecryptionService().decrypt_file(
        encryption.output_path, _accepted_key(), output_directory=destination
    )
    with pytest.raises(FileExistsError):
        FileDecryptionService().decrypt_file(
            encryption.output_path, _accepted_key(), output_directory=destination
        )


def test_no_eve_bb84_allows_encryption_with_acceptable_qber(tmp_path: Path) -> None:
    _, result = _encrypt_file(tmp_path, "accepted.txt", b"accepted")

    assert result.rejected is False
    assert result.qber == 0.0
    assert result.security_decision.accepted is True
    assert result.encryption_completed is True


def test_eve_high_qber_rejects_encryption_without_deriving_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import src.file_crypto.service as service_module

    input_path = tmp_path / "intercepted.txt"
    input_path.write_bytes(b"do not encrypt")
    derive_called = False

    def unexpected_derivation(*args, **kwargs):
        nonlocal derive_called
        derive_called = True
        raise AssertionError("Rejected BB84 material must not be derived.")

    monkeypatch.setattr(service_module, "derive_aes256_key", unexpected_derivation)
    result = FileEncryptionService(bb84_bit_count=4_000).encrypt_file(
        input_path, eve_enabled=True
    )

    assert result.success is False
    assert result.rejected is True
    assert result.qber > result.security_decision.threshold
    assert result.encryption_completed is False
    assert derive_called is False
    assert not (tmp_path / "intercepted.txt.enc").exists()


def test_structured_results_never_include_secret_key_material(tmp_path: Path) -> None:
    _, encryption = _encrypt_file(tmp_path, "private.txt", b"private")
    decryption = _decrypt_to_new_directory(tmp_path, encryption.output_path)

    encryption_data = asdict(encryption)
    decryption_data = asdict(decryption)
    assert "derived_key" not in encryption_data
    assert "alice_bits" not in encryption_data
    assert "bob_bits" not in encryption_data
    assert not any(isinstance(value, bytes) for value in encryption_data.values())
    assert not any(isinstance(value, bytes) for value in decryption_data.values())
