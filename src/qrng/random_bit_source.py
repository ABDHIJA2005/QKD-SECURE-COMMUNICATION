"""Random-bit source interfaces used by the QKD simulation.

``SoftwareRandomBitSource`` is intended for simulation and development only.
It is not a physical avalanche-noise QRNG.  A future hardware source will
implement :class:`RandomBitSource` and supply experimentally generated random
bits without requiring changes to BB84 consumers.
"""

from abc import ABC, abstractmethod
import secrets


class RandomBitSource(ABC):
    """Contract for components that provide binary bits to protocol modules."""

    @abstractmethod
    def generate_bits(self, n: int) -> list[int]:
        """Return exactly ``n`` binary integer bits (each ``0`` or ``1``)."""


class SoftwareRandomBitSource(RandomBitSource):
    """CSPRNG-backed random-bit source for simulation and development.

    This implementation is not the physical avalanche-noise QRNG.  Future
    hardware implementations will provide experimentally generated bits
    through the same :class:`RandomBitSource` interface.
    """

    def generate_bits(self, n: int) -> list[int]:
        """Return exactly ``n`` CSPRNG-generated binary integer bits.

        Raises:
            TypeError: If ``n`` is not an integer or is a boolean.
            ValueError: If ``n`` is not positive.
        """
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("n must be a positive integer.")
        if n <= 0:
            raise ValueError("n must be a positive integer.")

        return [secrets.randbits(1) for _ in range(n)]
