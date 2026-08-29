"""Shared BB84 basis definitions."""

from enum import Enum


class Basis(str, Enum):
    """The two BB84 polarization bases used by the classical simulation."""

    RECTILINEAR = "+"
    DIAGONAL = "×"

    @classmethod
    def from_random_bit(cls, bit: int) -> "Basis":
        """Map a binary random value to one of the two BB84 bases."""
        return cls.RECTILINEAR if bit == 0 else cls.DIAGONAL
