"""File encryption services that connect BB84, HKDF, and AES-256-GCM.

Encrypted file format (version 1)::

    b"QFE1" || AES_GCM_ENCRYPTED_PAYLOAD

The AES-GCM plaintext is ``filename_length (2 bytes) || UTF-8 filename ||
raw_file_bytes``. Filename metadata and file bytes are therefore both
authenticated by AES-GCM. Neither the AES key nor BB84 key material is stored
in this format or returned in service result objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag

from src.bb84 import BB84Simulation
from src.crypto import decrypt, derive_aes256_key, encrypt
from src.qrng import RandomBitSource
from src.security import DEFAULT_QBER_THRESHOLD, SecurityDecision

if TYPE_CHECKING:
    from src.bb84 import BB84SimulationMetadata, BB84SimulationResult


FILE_FORMAT_MAGIC = b"QFE1"
FILENAME_LENGTH_BYTES = 2


@dataclass(frozen=True)
class FileEncryptionResult:
    """Non-secret outcome of an encryption attempt, suitable for a GUI."""

    success: bool
    rejected: bool
    input_filename: str
    input_file_size: int
    output_filename: str | None
    output_file_size: int | None
    transmitted_bits: int
    matching_basis_count: int
    sifted_key_length: int
    qber: float
    qber_percentage: str
    eve_enabled: bool
    security_decision: SecurityDecision
    encryption_completed: bool
    output_path: Path | None


@dataclass(frozen=True)
class FileDecryptionResult:
    """Non-secret outcome of a decryption attempt, suitable for a GUI."""

    success: bool
    input_filename: str
    output_filename: str | None
    output_file_size: int | None
    authentication_verified: bool
    decryption_completed: bool
    output_path: Path | None
    error: str | None = None


class FileEncryptionService:
    """Encrypt files only after a BB84 run passes its QBER security decision."""

    def __init__(
        self,
        random_bit_source: RandomBitSource | None = None,
        *,
        bb84_bit_count: int = 4_096,
        qber_threshold: float = DEFAULT_QBER_THRESHOLD,
    ) -> None:
        if isinstance(bb84_bit_count, bool) or not isinstance(bb84_bit_count, int):
            raise TypeError("bb84_bit_count must be a positive integer.")
        if bb84_bit_count <= 0:
            raise ValueError("bb84_bit_count must be a positive integer.")
        self._random_bit_source = random_bit_source
        self._bb84_bit_count = bb84_bit_count
        self._qber_threshold = qber_threshold

    def encrypt_file(
        self,
        input_path: str | Path,
        *,
        eve_enabled: bool = False,
        output_directory: str | Path | None = None,
        bb84_result: BB84SimulationResult | None = None,
    ) -> FileEncryptionResult:
        """Encrypt one file after an accepted BB84 run.

        ``bb84_result`` may be supplied by a caller such as the UI to reuse a
        recently displayed run. When omitted, the service performs its own
        BB84 run as before.
        """
        source_path = _require_regular_file(input_path)
        source_bytes = source_path.read_bytes()
        if bb84_result is None:
            simulation = BB84Simulation(
                self._random_bit_source,
                eve_enabled=eve_enabled,
                qber_threshold=self._qber_threshold,
            )
            bb84_result = simulation.run(self._bb84_bit_count)
        metadata = bb84_result.metadata

        if not metadata.security_decision.accepted:
            return _encryption_result(
                metadata,
                input_filename=source_path.name,
                input_file_size=len(source_bytes),
            )

        derived_key = derive_aes256_key(
            bb84_result.sifted_key.alice_bits, metadata.security_decision
        )
        envelope = FILE_FORMAT_MAGIC + encrypt(
            _encode_file_plaintext(source_path.name, source_bytes), derived_key
        )
        destination_directory = _require_output_directory(output_directory, source_path.parent)
        destination_path = destination_directory / f"{source_path.name}.enc"
        _write_new_file(destination_path, envelope)

        return _encryption_result(
            metadata,
            input_filename=source_path.name,
            input_file_size=len(source_bytes),
            output_path=destination_path,
            output_file_size=len(envelope),
        )


class FileDecryptionService:
    """Decrypt authenticated file envelopes without overwriting existing files."""

    def decrypt_file(
        self,
        encrypted_path: str | Path,
        key: bytes,
        *,
        output_directory: str | Path | None = None,
    ) -> FileDecryptionResult:
        """Decrypt an envelope and write plaintext only after authentication."""
        source_path = _require_regular_file(encrypted_path)
        encrypted_data = source_path.read_bytes()

        try:
            if not encrypted_data.startswith(FILE_FORMAT_MAGIC):
                raise ValueError("Unsupported encrypted file format.")
            plaintext = decrypt(encrypted_data[len(FILE_FORMAT_MAGIC) :], key)
        except InvalidTag:
            return _decryption_failure(source_path.name, "Authentication failed.")
        except (TypeError, ValueError, UnicodeDecodeError) as error:
            return _decryption_failure(source_path.name, str(error))

        try:
            filename, file_bytes = _decode_file_plaintext(plaintext)
        except (ValueError, UnicodeDecodeError) as error:
            return _decryption_failure(
                source_path.name, str(error), authentication_verified=True
            )

        destination_directory = _require_output_directory(output_directory, source_path.parent)
        destination_path = destination_directory / filename
        _write_new_file(destination_path, file_bytes)
        return FileDecryptionResult(
            success=True,
            input_filename=source_path.name,
            output_filename=filename,
            output_file_size=len(file_bytes),
            authentication_verified=True,
            decryption_completed=True,
            output_path=destination_path,
        )


def _encryption_result(
    metadata: BB84SimulationMetadata,
    *,
    input_filename: str,
    input_file_size: int,
    output_path: Path | None = None,
    output_file_size: int | None = None,
) -> FileEncryptionResult:
    """Create a result without including raw or derived key material."""
    completed = output_path is not None
    return FileEncryptionResult(
        success=completed,
        rejected=not metadata.security_decision.accepted,
        input_filename=input_filename,
        input_file_size=input_file_size,
        output_filename=output_path.name if output_path else None,
        output_file_size=output_file_size,
        transmitted_bits=metadata.transmitted_bits,
        matching_basis_count=metadata.matching_basis_count,
        sifted_key_length=metadata.sifted_key_length,
        qber=metadata.qber,
        qber_percentage=metadata.qber_percentage,
        eve_enabled=metadata.eve_enabled,
        security_decision=metadata.security_decision,
        encryption_completed=completed,
        output_path=output_path,
    )


def _encode_file_plaintext(filename: str, file_bytes: bytes) -> bytes:
    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 2**(FILENAME_LENGTH_BYTES * 8) - 1:
        raise ValueError("Filename is too long for the encrypted file format.")
    return len(filename_bytes).to_bytes(FILENAME_LENGTH_BYTES, "big") + filename_bytes + file_bytes


def _decode_file_plaintext(plaintext: bytes) -> tuple[str, bytes]:
    if len(plaintext) < FILENAME_LENGTH_BYTES:
        raise ValueError("Encrypted file metadata is incomplete.")
    filename_length = int.from_bytes(plaintext[:FILENAME_LENGTH_BYTES], "big")
    filename_end = FILENAME_LENGTH_BYTES + filename_length
    if filename_length == 0 or filename_end > len(plaintext):
        raise ValueError("Encrypted file metadata contains an invalid filename.")
    filename = plaintext[FILENAME_LENGTH_BYTES:filename_end].decode("utf-8")
    if not _is_safe_filename(filename):
        raise ValueError("Encrypted file metadata contains an unsafe filename.")
    return filename, plaintext[filename_end:]


def _is_safe_filename(filename: str) -> bool:
    return (
        bool(filename)
        and filename not in {".", ".."}
        and "/" not in filename
        and "\\" not in filename
        and "\x00" not in filename
        and Path(filename).name == filename
    )


def _require_regular_file(path: str | Path) -> Path:
    resolved_path = Path(path)
    if not resolved_path.is_file():
        raise FileNotFoundError(f"Input file does not exist or is not a file: {resolved_path}")
    return resolved_path


def _require_output_directory(
    output_directory: str | Path | None, default_directory: Path
) -> Path:
    directory = Path(output_directory) if output_directory is not None else default_directory
    if not directory.is_dir():
        raise NotADirectoryError(f"Output directory does not exist: {directory}")
    return directory


def _write_new_file(path: Path, content: bytes) -> None:
    """Write a new file atomically with respect to accidental overwrite."""
    with path.open("xb") as output_file:
        output_file.write(content)


def _decryption_failure(
    input_filename: str, error: str, *, authentication_verified: bool = False
) -> FileDecryptionResult:
    return FileDecryptionResult(
        success=False,
        input_filename=input_filename,
        output_filename=None,
        output_file_size=None,
        authentication_verified=authentication_verified,
        decryption_completed=False,
        output_path=None,
        error=error,
    )
