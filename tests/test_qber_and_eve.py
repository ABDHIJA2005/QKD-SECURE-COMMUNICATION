"""Tests for QBER reporting and the BB84 intercept-resend attack."""

import pytest

from src.attacks import InterceptResendEve
from src.bb84 import BB84Simulation, Basis
from src.qrng import RandomBitSource
from src.security import (
    DEFAULT_QBER_THRESHOLD,
    assess_key_security,
    calculate_qber,
    qber_as_percentage,
)


class SequenceBitSource(RandomBitSource):
    """Deterministic source for testing protocol choices and measurements."""

    def __init__(self, values: list[int]) -> None:
        self._values = values
        self._position = 0
        self.calls: list[int] = []

    def generate_bits(self, n: int) -> list[int]:
        self.calls.append(n)
        end = self._position + n
        if end > len(self._values):
            raise AssertionError("Test source did not receive enough values.")
        result = self._values[self._position : end]
        self._position = end
        return result


def test_qber_is_zero_when_no_sifted_bits_differ() -> None:
    assert calculate_qber([0, 1, 1], [0, 1, 1]) == 0.0


def test_qber_is_one_when_all_sifted_bits_differ() -> None:
    assert calculate_qber([0, 1, 1], [1, 0, 0]) == 1.0


def test_qber_calculates_known_partial_error_rate_without_rounding() -> None:
    qber = calculate_qber([0, 1, 1, 0], [0, 0, 1, 1])

    assert qber == 0.5
    assert qber_as_percentage(qber) == "50.00%"


def test_qber_handles_an_empty_sifted_key_safely() -> None:
    assert calculate_qber([], []) == 0.0


def test_qber_rejects_sifted_keys_with_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        calculate_qber([0, 1], [0])


def test_eve_disabled_keeps_sifted_keys_matching() -> None:
    result = BB84Simulation().run(2_000)

    assert result.sifted_key.alice_bits == result.sifted_key.bob_bits
    assert result.metadata.qber == 0.0
    assert result.metadata.eve_enabled is False


def test_eve_chooses_bases_and_measures_according_to_bb84_rules() -> None:
    source = SequenceBitSource([0, 0, 0])
    eve = InterceptResendEve(source)

    result = eve.intercept_and_resend(
        (0, 1), (Basis.RECTILINEAR, Basis.DIAGONAL)
    )

    assert result.eve_bases == (Basis.RECTILINEAR, Basis.RECTILINEAR)
    assert result.eve_measurements == (0, 0)
    assert source.calls == [2, 1]


def test_eve_is_not_a_simple_random_bit_flipper_when_bases_match() -> None:
    source = SequenceBitSource([0, 1])
    eve = InterceptResendEve(source)

    result = eve.intercept_and_resend(
        (0, 1), (Basis.RECTILINEAR, Basis.DIAGONAL)
    )

    assert result.eve_measurements == (0, 1)
    assert result.eve_bases == (Basis.RECTILINEAR, Basis.DIAGONAL)
    assert source.calls == [2]


def test_intercept_resend_produces_approximately_25_percent_qber() -> None:
    result = BB84Simulation(eve_enabled=True).run(10_000)

    assert result.metadata.eve_enabled is True
    assert result.metadata.sifted_key_length > 2_000
    assert 0.19 <= result.metadata.qber <= 0.31


def test_eve_enabled_simulation_produces_sifted_key_errors() -> None:
    result = BB84Simulation(eve_enabled=True).run(4_000)

    assert result.metadata.qber > 0.0
    assert result.sifted_key.alice_bits != result.sifted_key.bob_bits


def test_metadata_contains_non_secret_protocol_summary() -> None:
    # Alice bits, Alice bases, Bob bases. All bases match, so no extra draws.
    source = SequenceBitSource([0, 1, 0, 0, 1, 0, 0, 1, 0])
    result = BB84Simulation(source).run(3)

    assert result.metadata.transmitted_bits == 3
    assert result.metadata.matching_basis_count == 3
    assert result.metadata.sifted_key_length == 3
    assert result.metadata.qber == 0.0
    assert result.metadata.qber_percentage == "0.00%"
    assert result.metadata.security_decision.status == "accepted"


def test_security_accepts_qber_at_or_below_the_configured_threshold() -> None:
    assert assess_key_security(DEFAULT_QBER_THRESHOLD).accepted is True
    assert assess_key_security(0.05, threshold=0.10).accepted is True


def test_security_rejects_qber_above_the_configured_threshold() -> None:
    decision = assess_key_security(0.12, threshold=DEFAULT_QBER_THRESHOLD)

    assert decision.accepted is False
    assert decision.status == "rejected"
