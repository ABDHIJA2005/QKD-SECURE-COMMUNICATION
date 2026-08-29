"""QBER calculation and simplified educational key-acceptance decisions."""

from dataclasses import dataclass
from math import isfinite
from typing import Sequence


DEFAULT_QBER_THRESHOLD = 0.11


@dataclass(frozen=True)
class SecurityDecision:
    """Non-secret outcome of comparing a QBER value with a threshold."""

    qber: float
    threshold: float
    accepted: bool

    @property
    def status(self) -> str:
        """Return a GUI-friendly status label without revealing key material."""
        return "accepted" if self.accepted else "rejected"


def calculate_qber(alice_sifted_bits: Sequence[int], bob_sifted_bits: Sequence[int]) -> float:
    """Return the exact ratio of differing sifted bits.

    An empty sifted key has no observed disagreements, so it returns ``0.0``.
    Callers should separately decide whether a usable key was produced.

    Raises:
        ValueError: If the two sequences have different lengths.
    """
    if len(alice_sifted_bits) != len(bob_sifted_bits):
        raise ValueError("Alice and Bob sifted keys must have equal lengths.")
    if not alice_sifted_bits:
        return 0.0

    differences = sum(
        alice_bit != bob_bit
        for alice_bit, bob_bit in zip(alice_sifted_bits, bob_sifted_bits, strict=True)
    )
    return differences / len(alice_sifted_bits)


def qber_as_percentage(qber: float, decimal_places: int = 2) -> str:
    """Format QBER for display without changing its internal value."""
    _validate_qber(qber)
    return f"{qber:.{decimal_places}%}"


def assess_key_security(
    qber: float, threshold: float = DEFAULT_QBER_THRESHOLD
) -> SecurityDecision:
    """Accept QBER at or below ``threshold`` in this simplified model.

    This educational threshold check is not a complete real-world QKD security
    proof and must not be treated as one.
    """
    _validate_qber(qber)
    _validate_qber(threshold)
    return SecurityDecision(qber=qber, threshold=threshold, accepted=qber <= threshold)


def _validate_qber(value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("QBER values must be numeric values between 0 and 1.")
    if not isfinite(value) or not 0 <= value <= 1:
        raise ValueError("QBER values must be between 0 and 1.")
