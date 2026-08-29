"""Services for encrypting and decrypting files with BB84-derived keys."""

from .service import (
    FILE_FORMAT_MAGIC,
    FileDecryptionResult,
    FileDecryptionService,
    FileEncryptionResult,
    FileEncryptionService,
)

__all__ = [
    "FILE_FORMAT_MAGIC",
    "FileDecryptionResult",
    "FileDecryptionService",
    "FileEncryptionResult",
    "FileEncryptionService",
]
