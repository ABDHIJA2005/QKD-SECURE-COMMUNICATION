"""Educational BB84 intercept-resend attacker."""

from dataclasses import dataclass

from src.bb84.basis import Basis
from src.qrng import RandomBitSource


@dataclass(frozen=True)
class EveInterceptionResult:
    """Internal state Eve prepares for Bob after intercepting a transmission."""

    eve_bases: tuple[Basis, ...]
    eve_measurements: tuple[int, ...]


class InterceptResendEve:
    """Model Eve measuring each state, then resending her measured state.

    The model is classical and educational. Eve chooses a fresh basis for
    every intercepted state; a mismatched measurement basis produces a fresh
    random result through the supplied :class:`RandomBitSource`.
    """

    def __init__(self, random_bit_source: RandomBitSource) -> None:
        self.random_bit_source = random_bit_source

    def intercept_and_resend(
        self, alice_bits: tuple[int, ...], alice_bases: tuple[Basis, ...]
    ) -> EveInterceptionResult:
        """Measure Alice's states and return the states Eve resends to Bob."""
        if len(alice_bits) != len(alice_bases):
            raise ValueError("Alice bits and bases must have equal lengths.")

        eve_bases = tuple(
            Basis.from_random_bit(bit)
            for bit in self.random_bit_source.generate_bits(len(alice_bits))
        )
        eve_measurements = tuple(
            self._measure(alice_bit, alice_basis, eve_basis)
            for alice_bit, alice_basis, eve_basis in zip(
                alice_bits, alice_bases, eve_bases, strict=True
            )
        )
        return EveInterceptionResult(eve_bases=eve_bases, eve_measurements=eve_measurements)

    def _measure(self, bit: int, prepared_basis: Basis, measurement_basis: Basis) -> int:
        if prepared_basis is measurement_basis:
            return bit
        return self.random_bit_source.generate_bits(1)[0]
