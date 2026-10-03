"""Qiskit-backed implementation of the BB84 protocol using quantum circuits and AerSimulator.

This module models state preparation (|0>, |1>, |+>, |->) and measurement basis
rotation (rectilinear vs diagonal) using genuine quantum circuits simulated on
Qiskit's AerSimulator backend.
"""

from __future__ import annotations

import site
import sys
from collections.abc import Sequence
from typing import Any

# Ensure active interpreter's site-packages takes precedence over foreign venv paths in sys.path
for _site_pkg in site.getsitepackages():
    if _site_pkg in sys.path:
        sys.path.remove(_site_pkg)
        sys.path.insert(1, _site_pkg)

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from src.attacks import EveInterceptionResult
from src.qrng import RandomBitSource, SoftwareRandomBitSource
from src.security import (
    DEFAULT_QBER_THRESHOLD,
    assess_key_security,
    calculate_qber,
    qber_as_percentage,
)

from .basis import Basis
from .simulation import (
    BB84Participant,
    BB84SimulationMetadata,
    BB84SimulationResult,
    SiftedKeyMaterial,
)

SUPPORTED_TRANSMISSION_SIZES: tuple[int, ...] = (1000, 2000, 3000)
DEFAULT_QISKIT_TRANSMISSION_SIZE: int = 1000


class QiskitBB84Simulation:
    """Run the BB84 workflow using Qiskit quantum circuits on AerSimulator.

    Explicitly supports manageable transmission sizes:
    - 1000 bits
    - 2000 bits
    - 3000 bits

    Supports both:
    1. No Eve (Alice -> Bob)
    2. Eve enabled (Alice -> Eve Qiskit measurement -> Eve Qiskit resend -> Bob)

    Alice's raw bits and basis choices prepare single-qubit quantum states:
    - Rectilinear:
      * bit 0 -> |0> (ground state, no gate)
      * bit 1 -> |1> (Pauli-X gate)
    - Diagonal:
      * bit 0 -> |+> (Hadamard gate H)
      * bit 1 -> |-> (Pauli-X gate, then Hadamard gate H)

    Bob's (and Eve's) basis choices determine the measurement circuit:
    - Rectilinear: measure directly in standard computational (Z) basis
    - Diagonal: apply Hadamard gate H, then measure in computational basis
    """

    SUPPORTED_TRANSMISSION_SIZES: tuple[int, ...] = SUPPORTED_TRANSMISSION_SIZES
    DEFAULT_TRANSMISSION_SIZE: int = DEFAULT_QISKIT_TRANSMISSION_SIZE

    @classmethod
    def is_supported_transmission_size(cls, n: int) -> bool:
        """Return True if ``n`` is one of the standard supported transmission sizes (1000, 2000, 3000)."""
        return n in cls.SUPPORTED_TRANSMISSION_SIZES

    def __init__(
        self,
        random_bit_source: RandomBitSource | None = None,
        *,
        backend: Any = None,
        eve_enabled: bool = False,
        qber_threshold: float = DEFAULT_QBER_THRESHOLD,
    ) -> None:
        source = random_bit_source or SoftwareRandomBitSource()
        self.alice = BB84Participant("Alice", source)
        self.bob = BB84Participant("Bob", source)
        self.eve_source = source
        self.backend = backend or AerSimulator()
        self.eve_enabled = eve_enabled
        self.qber_threshold = qber_threshold
        assess_key_security(0.0, qber_threshold)

    def run(self, n: int) -> BB84SimulationResult:
        """Simulate BB84 state preparation, Aer quantum measurement, and basis sifting.

        Raises:
            TypeError: If ``n`` is not an integer or is a boolean.
            ValueError: If ``n`` is not positive.
        """
        self._validate_count(n)

        alice_bits = self.alice.generate_raw_bits(n)
        alice_bases = self.alice.generate_bases(n)
        bob_bases = self.bob.generate_bases(n)

        if self.eve_enabled:
            eve_bases = tuple(
                Basis.from_random_bit(bit)
                for bit in self.eve_source.generate_bits(n)
            )
            # Step 1 & 3: Alice prepares Qiskit state -> Eve measures in chosen basis
            eve_measurements = self.measure_states(alice_bits, alice_bases, eve_bases)
            eve_interception = EveInterceptionResult(
                eve_bases=eve_bases,
                eve_measurements=eve_measurements,
            )
            # Step 4 & 5: Eve prepares new Qiskit state from measured bit & basis -> Bob measures
            bob_measurements = self.measure_states(eve_measurements, eve_bases, bob_bases)
        else:
            eve_interception = None
            bob_measurements = self.measure_states(alice_bits, alice_bases, bob_bases)

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
            eve_enabled=self.eve_enabled,
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

    def simulate_intercept_resend(
        self,
        alice_bits: Sequence[int],
        alice_bases: Sequence[Basis],
        eve_bases: Sequence[Basis],
        bob_bases: Sequence[Basis],
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """Run Alice -> Eve -> Bob quantum transmission and return (eve_measurements, bob_measurements)."""
        eve_measurements = self.measure_states(alice_bits, alice_bases, eve_bases)
        bob_measurements = self.measure_states(eve_measurements, eve_bases, bob_bases)
        return eve_measurements, bob_measurements


    def measure_states(
        self,
        alice_bits: Sequence[int],
        alice_bases: Sequence[Basis],
        bob_bases: Sequence[Basis],
        batch_size: int = 2000,
    ) -> tuple[int, ...]:
        """Execute Qiskit quantum circuits to simulate quantum transmission and measurement."""
        if not (len(alice_bits) == len(alice_bases) == len(bob_bases)):
            raise ValueError("alice_bits, alice_bases, and bob_bases must have equal lengths.")
        if len(alice_bits) == 0:
            return ()

        measurements: list[int] = []
        total = len(alice_bits)

        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            circuits = [
                self.build_qubit_circuit(alice_bits[i], alice_bases[i], bob_bases[i])
                for i in range(start, end)
            ]
            job = self.backend.run(circuits, shots=1)
            job_result = job.result()
            for idx in range(len(circuits)):
                counts = job_result.get_counts(idx)
                measured_bit = int(next(iter(counts.keys())))
                measurements.append(measured_bit)

        return tuple(measurements)

    @staticmethod
    def build_qubit_circuit(
        alice_bit: int, alice_basis: Basis, bob_basis: Basis
    ) -> QuantumCircuit:
        """Construct a 1-qubit Qiskit circuit for Alice's state preparation and Bob's basis measurement.

        Mapping:
        - Rectilinear preparation:
          * bit 0 -> |0> (ground state, no gate)
          * bit 1 -> |1> (Pauli-X gate)
        - Diagonal preparation:
          * bit 0 -> |+> (Hadamard gate H)
          * bit 1 -> |-> (Pauli-X gate, then Hadamard gate H)

        Measurement:
        - Rectilinear measurement: direct computational basis measurement
        - Diagonal measurement: apply Hadamard gate H before computational measurement
        """
        qc = QuantumCircuit(1, 1)

        # 1. State preparation (Alice)
        if alice_basis is Basis.RECTILINEAR:
            if alice_bit == 1:
                qc.x(0)
        elif alice_basis is Basis.DIAGONAL:
            if alice_bit == 1:
                qc.x(0)
            qc.h(0)
        else:
            raise ValueError(f"Unsupported Alice basis: {alice_basis}")

        # 2. Measurement basis rotation (Bob)
        if bob_basis is Basis.RECTILINEAR:
            pass
        elif bob_basis is Basis.DIAGONAL:
            qc.h(0)
        else:
            raise ValueError(f"Unsupported Bob basis: {bob_basis}")

        # 3. Measurement into classical register
        qc.measure(0, 0)
        return qc

    @staticmethod
    def _validate_count(n: int) -> None:
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("n must be a positive integer.")
        if n <= 0:
            raise ValueError("n must be a positive integer.")
