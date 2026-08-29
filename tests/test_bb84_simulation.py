"""Tests for the educational, no-Eve BB84 simulation."""

import pytest

from src.bb84 import BB84Simulation, Basis
from src.qrng import RandomBitSource


class SequenceBitSource(RandomBitSource):
    """Deterministic test double that records the abstraction's use."""

    def __init__(self, values: list[int]) -> None:
        self._values = values
        self._position = 0
        self.calls: list[int] = []

    def generate_bits(self, n: int) -> list[int]:
        self.calls.append(n)
        end = self._position + n
        if end > len(self._values):
            raise AssertionError("Test source did not receive enough values.")
        bits = self._values[self._position : end]
        self._position = end
        return bits


def test_parties_generate_requested_number_of_bits_and_bases() -> None:
    result = BB84Simulation().run(32)

    assert len(result.alice_bits) == 32
    assert len(result.alice_bases) == 32
    assert len(result.bob_bases) == 32
    assert len(result.bob_measurements) == 32


def test_all_basis_values_are_valid() -> None:
    result = BB84Simulation().run(64)

    assert set(result.alice_bases).issubset(set(Basis))
    assert set(result.bob_bases).issubset(set(Basis))
    assert {basis.value for basis in Basis} == {"+", "×"}


def test_matching_bases_produce_alice_bit_without_eve() -> None:
    result = BB84Simulation().run(64)

    for position in result.matching_positions:
        assert result.bob_measurements[position] == result.alice_bits[position]


def test_mismatched_bases_use_a_new_random_measurement_not_alice_bit() -> None:
    # Alice bits, Alice bases, Bob bases, then four mismatched measurements.
    source = SequenceBitSource(
        [0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0]
    )
    result = BB84Simulation(source).run(4)

    assert result.matching_positions == ()
    assert result.bob_measurements == (1, 1, 0, 0)
    assert result.bob_measurements != result.alice_bits
    assert source.calls == [4, 4, 4, 1, 1, 1, 1]


def test_sifting_retains_exactly_matching_basis_positions() -> None:
    # Alice bits, Alice bases, Bob bases, then one mismatched measurement.
    source = SequenceBitSource([0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1])
    result = BB84Simulation(source).run(4)

    assert result.matching_positions == (0, 2, 3)
    assert result.sifted_key.positions == (0, 2, 3)
    assert result.sifted_key.alice_bits == (0, 0, 1)
    assert result.sifted_key.bob_bits == (0, 0, 1)


def test_sifted_alice_and_bob_keys_match_without_eve() -> None:
    result = BB84Simulation().run(128)

    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits


@pytest.mark.parametrize("invalid_n", [0, -1, 1.5, "8", None, True])
def test_invalid_simulation_lengths_are_rejected(invalid_n: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        BB84Simulation().run(invalid_n)  # type: ignore[arg-type]


def test_repeated_simulations_work() -> None:
    simulation = BB84Simulation()

    first = simulation.run(16)
    second = simulation.run(31)

    assert len(first.alice_bits) == 16
    assert len(second.alice_bits) == 31
    assert first.sifted_key.alice_bits == first.sifted_key.bob_bits
    assert second.sifted_key.alice_bits == second.sifted_key.bob_bits


def test_simulation_uses_injected_random_bit_source() -> None:
    # All bases are rectilinear, so no extra mismatch measurements are needed.
    source = SequenceBitSource([0, 1, 0, 0, 0, 0, 0, 0, 0])
    simulation = BB84Simulation(source)
    result = simulation.run(3)

    assert simulation.alice.random_bit_source is source
    assert simulation.bob.random_bit_source is source
    assert source.calls == [3, 3, 3]
    assert result.alice_bits == (0, 1, 0)
