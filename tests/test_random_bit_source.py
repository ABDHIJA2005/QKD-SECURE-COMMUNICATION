"""Tests for simulation random-bit sources."""

from unittest.mock import patch

import pytest

from src.qrng import RandomBitSource, SoftwareRandomBitSource


def test_random_bit_source_is_an_interface() -> None:
    """The contract cannot be instantiated without an implementation."""
    with pytest.raises(TypeError):
        RandomBitSource()


@pytest.mark.parametrize("n", [1, 8, 128])
def test_generate_bits_returns_requested_length(n: int) -> None:
    bits = SoftwareRandomBitSource().generate_bits(n)

    assert len(bits) == n


def test_generate_bits_returns_only_binary_integers() -> None:
    bits = SoftwareRandomBitSource().generate_bits(256)

    assert all(isinstance(bit, int) and bit in (0, 1) for bit in bits)


def test_multiple_calls_work() -> None:
    source = SoftwareRandomBitSource()

    first = source.generate_bits(5)
    second = source.generate_bits(11)

    assert len(first) == 5
    assert len(second) == 11


@pytest.mark.parametrize("invalid_n", [0, -1, 1.5, "4", None, True])
def test_generate_bits_rejects_invalid_input(invalid_n: object) -> None:
    source = SoftwareRandomBitSource()

    with pytest.raises((TypeError, ValueError)):
        source.generate_bits(invalid_n)  # type: ignore[arg-type]


def test_generate_bits_uses_cryptographic_randomness_not_hard_coded_bits() -> None:
    """Bits returned by the source reflect values supplied by ``secrets``."""
    source = SoftwareRandomBitSource()

    with patch("src.qrng.random_bit_source.secrets.randbits", side_effect=[1, 0, 1]) as randbits:
        assert source.generate_bits(3) == [1, 0, 1]

    assert randbits.call_count == 3
    randbits.assert_called_with(1)
