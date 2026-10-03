"""Tests for the Qiskit-backed BB84 simulation."""

from __future__ import annotations

import site
import sys
import pytest

# Ensure active interpreter's site-packages takes precedence over foreign venv paths in sys.path
for _site_pkg in site.getsitepackages():
    if _site_pkg in sys.path:
        sys.path.remove(_site_pkg)
        sys.path.insert(1, _site_pkg)

from src.bb84 import (
    DEFAULT_QISKIT_TRANSMISSION_SIZE,
    SUPPORTED_TRANSMISSION_SIZES,
    Basis,
)
from src.bb84.qiskit_simulation import QiskitBB84Simulation
from src.qrng import RandomBitSource


class SequenceBitSource(RandomBitSource):
    """Deterministic test double for controlling bit and basis selections."""

    def __init__(self, values: list[int]) -> None:
        self._values = values
        self._position = 0
        self.calls: list[int] = []

    def generate_bits(self, n: int) -> list[int]:
        self.calls.append(n)
        end = self._position + n
        if end > len(self._values):
            raise AssertionError(
                f"Test source requested {n} bits, but only {len(self._values) - self._position} remain."
            )
        bits = self._values[self._position : end]
        self._position = end
        return bits


def test_matching_basis_deterministic_rectilinear_zero() -> None:
    """Alice bit=0 in rectilinear basis (|0>) measured by Bob in rectilinear basis -> 0."""
    sim = QiskitBB84Simulation()
    shots = 50
    alice_bits = (0,) * shots
    alice_bases = (Basis.RECTILINEAR,) * shots
    bob_bases = (Basis.RECTILINEAR,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert measurements == alice_bits
    assert set(measurements) == {0}


def test_matching_basis_deterministic_rectilinear_one() -> None:
    """Alice bit=1 in rectilinear basis (|1>) measured by Bob in rectilinear basis -> 1."""
    sim = QiskitBB84Simulation()
    shots = 50
    alice_bits = (1,) * shots
    alice_bases = (Basis.RECTILINEAR,) * shots
    bob_bases = (Basis.RECTILINEAR,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert measurements == alice_bits
    assert set(measurements) == {1}


def test_matching_basis_deterministic_diagonal_zero() -> None:
    """Alice bit=0 in diagonal basis (|+>) measured by Bob in diagonal basis -> 0."""
    sim = QiskitBB84Simulation()
    shots = 50
    alice_bits = (0,) * shots
    alice_bases = (Basis.DIAGONAL,) * shots
    bob_bases = (Basis.DIAGONAL,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert measurements == alice_bits
    assert set(measurements) == {0}


def test_matching_basis_deterministic_diagonal_one() -> None:
    """Alice bit=1 in diagonal basis (|->) measured by Bob in diagonal basis -> 1."""
    sim = QiskitBB84Simulation()
    shots = 50
    alice_bits = (1,) * shots
    alice_bases = (Basis.DIAGONAL,) * shots
    bob_bases = (Basis.DIAGONAL,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert measurements == alice_bits
    assert set(measurements) == {1}


def test_mismatched_basis_behavior_rectilinear_to_diagonal() -> None:
    """Rectilinear prepared states measured in diagonal basis produce ~50/50 outcomes."""
    sim = QiskitBB84Simulation()
    shots = 1000
    alice_bits = (0,) * (shots // 2) + (1,) * (shots // 2)
    alice_bases = (Basis.RECTILINEAR,) * shots
    bob_bases = (Basis.DIAGONAL,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert len(measurements) == shots
    zeros = measurements.count(0)
    ones = measurements.count(1)
    # Check approximately balanced with statistical tolerance (between 40% and 60%)
    assert 400 <= zeros <= 600
    assert 400 <= ones <= 600


def test_mismatched_basis_behavior_diagonal_to_rectilinear() -> None:
    """Diagonal prepared states measured in rectilinear basis produce ~50/50 outcomes."""
    sim = QiskitBB84Simulation()
    shots = 1000
    alice_bits = (0,) * (shots // 2) + (1,) * (shots // 2)
    alice_bases = (Basis.DIAGONAL,) * shots
    bob_bases = (Basis.RECTILINEAR,) * shots

    measurements = sim.measure_states(alice_bits, alice_bases, bob_bases)

    assert len(measurements) == shots
    zeros = measurements.count(0)
    ones = measurements.count(1)
    # Check approximately balanced with statistical tolerance (between 40% and 60%)
    assert 400 <= zeros <= 600
    assert 400 <= ones <= 600


def test_sifting_retains_exact_matching_positions() -> None:
    """Sifting correctly retains matching basis positions and discards mismatched positions."""
    # Alice bits: 0, 1, 0, 1
    # Alice bases: 0(+), 1(x), 0(+), 1(x)
    # Bob bases:   0(+), 0(+), 0(+), 1(x)
    # Matching positions: 0, 2, 3 (position 1 has mismatched bases: x vs +)
    source = SequenceBitSource([0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1])
    sim = QiskitBB84Simulation(source)

    result = sim.run(4)

    assert result.matching_positions == (0, 2, 3)
    assert result.sifted_key.positions == (0, 2, 3)
    assert result.sifted_key.alice_bits == (0, 0, 1)
    assert result.sifted_key.bob_bits == (0, 0, 1)
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


def test_large_random_simulation_without_eve() -> None:
    """1000-bit simulation produces ~50% sifted key with 0% QBER and matching keys."""
    sim = QiskitBB84Simulation()
    n = 1000

    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    # Sifted key is approximately 50% of transmitted bits (tolerance 400 to 600)
    assert 400 <= result.metadata.sifted_key_length <= 600
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    # Without Eve, QBER is exactly 0.0%
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.security_decision.status == "accepted"
    # Alice and Bob sifted keys match identically
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


@pytest.mark.parametrize("invalid_n", [0, -1, -10, 1.5, "100", None, True])
def test_invalid_simulation_counts_are_rejected(invalid_n: object) -> None:
    """Invalid bit counts raise TypeError or ValueError."""
    with pytest.raises((TypeError, ValueError)):
        QiskitBB84Simulation().run(invalid_n)  # type: ignore[arg-type]


def test_circuit_construction_helper() -> None:
    """build_qubit_circuit constructs valid 1-qubit 1-clbit quantum circuits."""
    for alice_bit in (0, 1):
        for alice_basis in (Basis.RECTILINEAR, Basis.DIAGONAL):
            for bob_basis in (Basis.RECTILINEAR, Basis.DIAGONAL):
                qc = QiskitBB84Simulation.build_qubit_circuit(
                    alice_bit, alice_basis, bob_basis
                )
                assert qc.num_qubits == 1
                assert qc.num_clbits == 1


def test_qiskit_eve_disabled_large_run() -> None:
    """Eve disabled: 1000 qubits yields ~50% sifted key, 0% QBER, accepted security."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    result = sim.run(1000)

    assert result.metadata.eve_enabled is False
    assert result.eve_interception is None
    assert 400 <= result.metadata.sifted_key_length <= 600
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.security_decision.status == "accepted"
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


def test_qiskit_eve_enabled_produces_rejection_and_approx_25_percent_qber() -> None:
    """Eve enabled: 1000 qubits yields ~25% QBER and triggers security rejection."""
    sim = QiskitBB84Simulation(eve_enabled=True)
    result = sim.run(1000)

    assert result.metadata.eve_enabled is True
    assert result.eve_interception is not None
    assert len(result.eve_interception.eve_bases) == 1000
    assert len(result.eve_interception.eve_measurements) == 1000
    assert 400 <= result.metadata.sifted_key_length <= 600
    # QBER should be substantially above 0% and statistically consistent with ~25%
    assert 0.18 <= result.metadata.qber <= 0.32
    assert result.metadata.security_decision.accepted is False
    assert result.metadata.security_decision.status == "rejected"
    assert result.sifted_key.alice_bits != result.sifted_key.bob_bits


def test_qiskit_eve_basis_choices_are_independent_of_alice() -> None:
    """Eve independently chooses bases; choices are not deterministically equal to Alice."""
    sim = QiskitBB84Simulation(eve_enabled=True)
    result = sim.run(1000)

    assert result.eve_interception is not None
    eve_bases = result.eve_interception.eve_bases
    alice_bases = result.alice_bases

    # Eve should have selected both bases
    assert set(eve_bases) == {Basis.RECTILINEAR, Basis.DIAGONAL}
    # Eve does not copy Alice
    assert eve_bases != alice_bases
    matching = sum(1 for eb, ab in zip(eve_bases, alice_bases, strict=True) if eb is ab)
    # Natural agreement between independent 50/50 choices should be ~50%
    assert 400 <= matching <= 600


def test_controlled_intercept_resend_preserves_bit_when_eve_matches_alice_basis() -> None:
    """When Eve coincidentally chooses Alice's basis, her measurement and resend preserves the bit."""
    sim = QiskitBB84Simulation()
    shots = 50

    # 1. Rectilinear bit 0
    e_meas, b_meas = sim.simulate_intercept_resend(
        (0,) * shots,
        (Basis.RECTILINEAR,) * shots,
        (Basis.RECTILINEAR,) * shots,
        (Basis.RECTILINEAR,) * shots,
    )
    assert e_meas == (0,) * shots
    assert b_meas == (0,) * shots

    # 2. Rectilinear bit 1
    e_meas, b_meas = sim.simulate_intercept_resend(
        (1,) * shots,
        (Basis.RECTILINEAR,) * shots,
        (Basis.RECTILINEAR,) * shots,
        (Basis.RECTILINEAR,) * shots,
    )
    assert e_meas == (1,) * shots
    assert b_meas == (1,) * shots

    # 3. Diagonal bit 0
    e_meas, b_meas = sim.simulate_intercept_resend(
        (0,) * shots,
        (Basis.DIAGONAL,) * shots,
        (Basis.DIAGONAL,) * shots,
        (Basis.DIAGONAL,) * shots,
    )
    assert e_meas == (0,) * shots
    assert b_meas == (0,) * shots

    # 4. Diagonal bit 1
    e_meas, b_meas = sim.simulate_intercept_resend(
        (1,) * shots,
        (Basis.DIAGONAL,) * shots,
        (Basis.DIAGONAL,) * shots,
        (Basis.DIAGONAL,) * shots,
    )
    assert e_meas == (1,) * shots
    assert b_meas == (1,) * shots


def test_controlled_intercept_resend_distorts_state_when_eve_mismatches_alice_basis() -> None:
    """When Eve chooses the wrong basis, state collapse introduces errors even when Bob uses Alice's basis."""
    sim = QiskitBB84Simulation()
    shots = 1000

    # Alice: bit 1 in RECTILINEAR (|1>)
    # Eve: DIAGONAL (mismatched basis: collapses to |+> or |->)
    # Bob: RECTILINEAR (matches Alice's original basis)
    e_meas, b_meas = sim.simulate_intercept_resend(
        (1,) * shots,
        (Basis.RECTILINEAR,) * shots,
        (Basis.DIAGONAL,) * shots,
        (Basis.RECTILINEAR,) * shots,
    )

    # Eve measures in diagonal basis, so her measurements are ~50/50
    assert 400 <= e_meas.count(0) <= 600
    assert 400 <= e_meas.count(1) <= 600

    # Because Eve collapsed and resent in diagonal basis, Bob gets ~50% errors despite using Alice's basis!
    bob_zeros = b_meas.count(0)  # Errors (Alice sent 1)
    bob_ones = b_meas.count(1)   # Correct
    assert 400 <= bob_zeros <= 600
    assert 400 <= bob_ones <= 600


def test_supported_transmission_sizes_explicit() -> None:
    """The supported transmission sizes are explicitly (1000, 2000, 3000)."""
    assert SUPPORTED_TRANSMISSION_SIZES == (1000, 2000, 3000)
    assert QiskitBB84Simulation.SUPPORTED_TRANSMISSION_SIZES == (1000, 2000, 3000)
    assert QiskitBB84Simulation.DEFAULT_TRANSMISSION_SIZE == 1000
    assert DEFAULT_QISKIT_TRANSMISSION_SIZE == 1000
    for size in (1000, 2000, 3000):
        assert QiskitBB84Simulation.is_supported_transmission_size(size) is True
    assert QiskitBB84Simulation.is_supported_transmission_size(500) is False
    assert QiskitBB84Simulation.is_supported_transmission_size(10000) is False


def test_qiskit_transmission_size_1000_no_eve() -> None:
    """Test 1 (No Eve) - 1000 bits: transmitted=1000, sifted key ~50%, QBER=0%, matching keys."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    n = 1000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 400 <= result.metadata.sifted_key_length <= 600
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.security_decision.status == "accepted"
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


def test_qiskit_transmission_size_1000_with_eve() -> None:
    """Test 1 (Eve) - 1000 bits: transmitted=1000, sifted key ~50%, QBER ~25%, decision rejected."""
    sim = QiskitBB84Simulation(eve_enabled=True)
    n = 1000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 400 <= result.metadata.sifted_key_length <= 600
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert 0.18 <= result.metadata.qber <= 0.32
    assert result.metadata.security_decision.accepted is False
    assert result.metadata.security_decision.status == "rejected"
    assert result.sifted_key.alice_bits != result.sifted_key.bob_bits
    assert result.eve_interception is not None
    assert len(result.eve_interception.eve_bases) == n
    assert len(result.eve_interception.eve_measurements) == n


def test_qiskit_transmission_size_2000_no_eve() -> None:
    """Test 2 (No Eve) - 2000 bits: transmitted=2000, sifted key ~50%, QBER=0%, matching keys."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    n = 2000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 800 <= result.metadata.sifted_key_length <= 1200
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.security_decision.status == "accepted"
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


def test_qiskit_transmission_size_2000_with_eve() -> None:
    """Test 2 (Eve) - 2000 bits: transmitted=2000, sifted key ~50%, QBER ~25%, decision rejected."""
    sim = QiskitBB84Simulation(eve_enabled=True)
    n = 2000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 800 <= result.metadata.sifted_key_length <= 1200
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert 0.18 <= result.metadata.qber <= 0.32
    assert result.metadata.security_decision.accepted is False
    assert result.metadata.security_decision.status == "rejected"
    assert result.sifted_key.alice_bits != result.sifted_key.bob_bits
    assert result.eve_interception is not None
    assert len(result.eve_interception.eve_bases) == n
    assert len(result.eve_interception.eve_measurements) == n


def test_qiskit_transmission_size_3000_no_eve() -> None:
    """Test 3 (No Eve) - 3000 bits: transmitted=3000, sifted key ~50%, QBER=0%, matching keys."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    n = 3000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 1200 <= result.metadata.sifted_key_length <= 1800
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.security_decision.status == "accepted"
    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


def test_qiskit_transmission_size_3000_with_eve() -> None:
    """Test 3 (Eve) - 3000 bits: transmitted=3000, sifted key ~50%, QBER ~25%, decision rejected."""
    sim = QiskitBB84Simulation(eve_enabled=True)
    n = 3000
    result = sim.run(n)

    assert result.metadata.transmitted_bits == n
    assert 1200 <= result.metadata.sifted_key_length <= 1800
    assert result.metadata.matching_basis_count == result.metadata.sifted_key_length
    assert 0.18 <= result.metadata.qber <= 0.32
    assert result.metadata.security_decision.accepted is False
    assert result.metadata.security_decision.status == "rejected"
    assert result.sifted_key.alice_bits != result.sifted_key.bob_bits
    assert result.eve_interception is not None
    assert len(result.eve_interception.eve_bases) == n
    assert len(result.eve_interception.eve_measurements) == n


