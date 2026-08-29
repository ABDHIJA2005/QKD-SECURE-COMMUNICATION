"""Classical, educational simulation of the BB84 key-distribution protocol.

This module models BB84's preparation, measurement, and basis-sifting rules.
It is not a real quantum-cryptography implementation and it does not model
physical quantum states, devices, noise, or a hardware QRNG.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.qrng import RandomBitSource, SoftwareRandomBitSource
from src.security import (
    DEFAULT_QBER_THRESHOLD,
    SecurityDecision,
    assess_key_security,
    calculate_qber,
    qber_as_percentage,
)

from .basis import Basis

if TYPE_CHECKING:
    from src.attacks import EveInterceptionResult, InterceptResendEve


@dataclass(frozen=True)
class BB84Participant:
    """A BB84 party whose private choices come from a random-bit source."""

    name: str
    random_bit_source: RandomBitSource

    def generate_raw_bits(self, n: int) -> tuple[int, ...]:
        """Generate ``n`` private binary values."""
        return tuple(self.random_bit_source.generate_bits(n))

    def generate_bases(self, n: int) -> tuple[Basis, ...]:
        """Generate ``n`` private BB84 basis choices."""
        return tuple(
            Basis.from_random_bit(bit) for bit in self.random_bit_source.generate_bits(n)
        )


@dataclass(frozen=True)
class SiftedKeyMaterial:
    """Private key material retained at positions with matching bases."""

    positions: tuple[int, ...]
    alice_bits: tuple[int, ...]
    bob_bits: tuple[int, ...]


@dataclass(frozen=True)
class BB84SimulationMetadata:
    """Non-secret summary suitable for a future presentation layer."""

    transmitted_bits: int
    matching_basis_count: int
    sifted_key_length: int
    qber: float
    qber_percentage: str
    eve_enabled: bool
    security_decision: SecurityDecision


@dataclass(frozen=True)
class BB84SimulationResult:
    """Internal result of one simulation run, including test-visible secrets.

    These fields intentionally make protocol state available for verification.
    Future presentation layers must avoid exposing raw or sifted key material.
    """

    alice_bits: tuple[int, ...]
    alice_bases: tuple[Basis, ...]
    bob_bases: tuple[Basis, ...]
    bob_measurements: tuple[int, ...]
    matching_positions: tuple[int, ...]
    sifted_key: SiftedKeyMaterial
    eve_interception: EveInterceptionResult | None
    metadata: BB84SimulationMetadata


class BB84Simulation:
    """Run the no-Eve, classical educational BB84 workflow.

    Injecting a :class:`RandomBitSource` lets future simulations use a
    hardware QRNG without changing protocol consumers.  A later intercept-
    resend attack can extend the transmission stage without rewriting Alice,
    Bob, or sifting.
    """

    def __init__(
        self,
        random_bit_source: RandomBitSource | None = None,
        *,
        eve_enabled: bool = False,
        eve: InterceptResendEve | None = None,
        qber_threshold: float = DEFAULT_QBER_THRESHOLD,
    ) -> None:
        source = random_bit_source or SoftwareRandomBitSource()
        self.alice = BB84Participant("Alice", source)
        self.bob = BB84Participant("Bob", source)
        if eve is not None:
            self.eve = eve
        elif eve_enabled:
            from src.attacks import InterceptResendEve

            self.eve = InterceptResendEve(source)
        else:
            self.eve = None
        self.qber_threshold = qber_threshold
        assess_key_security(0.0, qber_threshold)

    def run(self, n: int) -> BB84SimulationResult:
        """Simulate preparation, measurement, and authenticated basis sifting.

        Raises:
            TypeError: If ``n`` is not an integer or is a boolean.
            ValueError: If ``n`` is not positive.
        """
        self._validate_count(n)

        alice_bits = self.alice.generate_raw_bits(n)
        alice_bases = self.alice.generate_bases(n)
        bob_bases = self.bob.generate_bases(n)
        eve_interception = (
            self.eve.intercept_and_resend(alice_bits, alice_bases) if self.eve else None
        )
        transmitted_bits = (
            eve_interception.eve_measurements if eve_interception else alice_bits
        )
        transmitted_bases = eve_interception.eve_bases if eve_interception else alice_bases
        bob_measurements = tuple(
            self._measure(transmitted_bit, transmitted_basis, bob_basis)
            for transmitted_bit, transmitted_basis, bob_basis in zip(
                transmitted_bits, transmitted_bases, bob_bases, strict=True
            )
        )
        matching_positions = tuple(
            index
            for index, (alice_basis, bob_basis) in enumerate(
                zip(alice_bases, bob_bases, strict=True)
            )
            if alice_basis is bob_basis
        )
        sifted_key = SiftedKeyMaterial(
            positions=matching_positions,
            alice_bits=tuple(alice_bits[index] for index in matching_positions),
            bob_bits=tuple(bob_measurements[index] for index in matching_positions),
        )
        qber = calculate_qber(sifted_key.alice_bits, sifted_key.bob_bits)
        security_decision = assess_key_security(qber, self.qber_threshold)
        metadata = BB84SimulationMetadata(
            transmitted_bits=n,
            matching_basis_count=len(matching_positions),
            sifted_key_length=len(sifted_key.alice_bits),
            qber=qber,
            qber_percentage=qber_as_percentage(qber),
            eve_enabled=eve_interception is not None,
            security_decision=security_decision,
        )

        return BB84SimulationResult(
            alice_bits=alice_bits,
            alice_bases=alice_bases,
            bob_bases=bob_bases,
            bob_measurements=bob_measurements,
            matching_positions=matching_positions,
            sifted_key=sifted_key,
            eve_interception=eve_interception,
            metadata=metadata,
        )

    def _measure(self, alice_bit: int, alice_basis: Basis, bob_basis: Basis) -> int:
        """Return Bob's result using the BB84 same/mismatched-basis rule."""
        if alice_basis is bob_basis:
            return alice_bit
        return self.bob.random_bit_source.generate_bits(1)[0]

    @staticmethod
    def _validate_count(n: int) -> None:
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("n must be a positive integer.")
        if n <= 0:
            raise ValueError("n must be a positive integer.")
