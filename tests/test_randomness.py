"""Tests for the NIST SP 800-22 randomness testing layer and CSV parsers."""

from __future__ import annotations

import site
import sys
from pathlib import Path

# Ensure active interpreter's site-packages takes precedence over foreign venv paths in sys.path
for _site_pkg in site.getsitepackages():
    if _site_pkg in sys.path:
        sys.path.remove(_site_pkg)
        sys.path.insert(1, _site_pkg)

import pytest

from src.randomness import (
    DEFAULT_ALPHA,
    NISTSuiteResult,
    NISTTestResult,
    TestStatus,
    block_frequency_test,
    find_dataset_path,
    monobit_frequency_test,
    parse_bit_csv,
    parse_bit_csv_text,
    run_nist_battery,
    runs_test,
    validate_bit_sequence,
)


# ==============================================================================
# A. CSV Parsing Tests
# ==============================================================================


def test_parse_valid_1024_dataset() -> None:
    """The 1024 professor CSV file parses into exactly 1024 binary bits."""
    path = find_dataset_path(1024)
    bits = parse_bit_csv(path, expected_count=1024)
    assert len(bits) == 1024
    assert set(bits).issubset({0, 1})
    assert bits[:10] == (0, 1, 1, 0, 0, 0, 1, 1, 1, 0)


def test_parse_valid_2048_dataset() -> None:
    """The 2048 professor CSV file parses into exactly 2048 binary bits."""
    path = find_dataset_path(2048)
    bits = parse_bit_csv(path, expected_count=2048)
    assert len(bits) == 2048
    assert set(bits).issubset({0, 1})
    assert bits[:10] == (0, 1, 1, 0, 0, 0, 1, 1, 1, 0)


def test_parse_valid_3072_dataset() -> None:
    """The 3072 professor CSV file parses into exactly 3072 binary bits."""
    path = find_dataset_path(3072)
    bits = parse_bit_csv(path, expected_count=3072)
    assert len(bits) == 3072
    assert set(bits).issubset({0, 1})
    assert bits[:10] == (0, 1, 1, 0, 0, 0, 1, 1, 1, 0)


def test_parse_csv_invalid_non_binary_value() -> None:
    """Non-binary values in the bit column raise ValueError."""
    csv_content = "bit_index,bit\n0,0\n1,2\n2,1\n"
    with pytest.raises(ValueError, match="Non-binary bit value '2'"):
        parse_bit_csv_text(csv_content)


def test_parse_csv_missing_bit_value() -> None:
    """Missing bit value raises ValueError."""
    csv_content = "bit_index,bit\n0,0\n1,\n2,1\n"
    with pytest.raises(ValueError, match="Missing bit value"):
        parse_bit_csv_text(csv_content)


def test_parse_csv_malformed_row() -> None:
    """Rows with fewer or more than 2 columns raise ValueError."""
    # Row with only 1 column
    with pytest.raises(ValueError, match="Malformed row"):
        parse_bit_csv_text("bit_index,bit\n0\n1,1\n")

    # Row with 3 columns
    with pytest.raises(ValueError, match="Malformed row"):
        parse_bit_csv_text("bit_index,bit\n0,0,extra\n1,1\n")


def test_parse_csv_incorrect_non_sequential_bit_index() -> None:
    """Skipped or out-of-order bit_index raises ValueError."""
    csv_content = "bit_index,bit\n0,0\n2,1\n"
    with pytest.raises(ValueError, match="Non-sequential bit_index"):
        parse_bit_csv_text(csv_content)

    csv_content_start_1 = "bit_index,bit\n1,0\n2,1\n"
    with pytest.raises(ValueError, match="Non-sequential bit_index"):
        parse_bit_csv_text(csv_content_start_1)


def test_parse_csv_missing_or_invalid_header() -> None:
    """Missing or incorrect header raises ValueError."""
    with pytest.raises(ValueError, match="Invalid CSV header"):
        parse_bit_csv_text("index,value\n0,0\n1,1\n")

    with pytest.raises(ValueError, match="CSV content is empty"):
        parse_bit_csv_text("")


def test_parse_csv_expected_count_mismatch() -> None:
    """If expected_count is provided and does not match, ValueError is raised."""
    csv_content = "bit_index,bit\n0,0\n1,1\n"
    with pytest.raises(ValueError, match="Expected 3 bits, but parsed 2"):
        parse_bit_csv_text(csv_content, expected_count=3)


def test_parse_csv_file_not_found() -> None:
    """Non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        parse_bit_csv("non_existent_file_path_12345.csv")


# ==============================================================================
# B. Input Validation Tests
# ==============================================================================


def test_validate_bit_sequence_valid() -> None:
    """Valid sequences of 0 and 1 are returned as a tuple of ints."""
    assert validate_bit_sequence([0, 1, 0, 1]) == (0, 1, 0, 1)
    assert validate_bit_sequence((1, 1, 0)) == (1, 1, 0)


@pytest.mark.parametrize(
    "invalid_input",
    [
        [],
        (),
        "",
        b"",
        [0, 1, 2],
        [0, -1, 1],
        [0.0, 1.0],
        [0, "1"],
        [True, False],  # Bools must not be accepted as bits
    ],
)
def test_validate_bit_sequence_invalid(invalid_input: object) -> None:
    """Invalid inputs raise TypeError or ValueError."""
    with pytest.raises((TypeError, ValueError)):
        validate_bit_sequence(invalid_input)  # type: ignore[arg-type]


# ==============================================================================
# C. Randomness Test Tests
# ==============================================================================


def test_balanced_pseudorandom_sequence_passes_tests() -> None:
    """A balanced, pseudo-random sequence passes Monobit, Block Frequency, and Runs tests."""
    import random

    rng = random.Random(42)
    sequence = rng.choices([0, 1], k=1000)

    res_mono = monobit_frequency_test(sequence)
    assert res_mono.status == TestStatus.PASS
    assert res_mono.passed is True
    assert res_mono.p_value is not None
    assert res_mono.p_value >= DEFAULT_ALPHA

    res_block = block_frequency_test(sequence, block_size=100)
    assert res_block.status == TestStatus.PASS
    assert res_block.passed is True
    assert res_block.p_value is not None
    assert res_block.p_value >= DEFAULT_ALPHA

    res_runs = runs_test(sequence)
    assert res_runs.status == TestStatus.PASS
    assert res_runs.passed is True
    assert res_runs.p_value is not None
    assert res_runs.p_value >= DEFAULT_ALPHA


def test_all_zero_sequence_fails_frequency_monobit() -> None:
    """An all-zero sequence has s_obs = sqrt(n) and fails Frequency Monobit with p-value near 0."""
    zeros = [0] * 1000
    res = monobit_frequency_test(zeros)
    assert res.status == TestStatus.FAIL
    assert res.passed is False
    assert res.p_value is not None
    assert res.p_value < 1e-10


def test_all_one_sequence_fails_frequency_monobit() -> None:
    """An all-ones sequence fails Frequency Monobit with p-value near 0."""
    ones = [1] * 1000
    res = monobit_frequency_test(ones)
    assert res.status == TestStatus.FAIL
    assert res.passed is False
    assert res.p_value is not None
    assert res.p_value < 1e-10


def test_strongly_biased_sequence_fails_monobit() -> None:
    """A strongly biased sequence (e.g. 90% ones) fails Frequency Monobit."""
    biased = [1] * 900 + [0] * 100
    res = monobit_frequency_test(biased)
    assert res.status == TestStatus.FAIL
    assert res.passed is False
    assert res.p_value is not None
    assert res.p_value < 0.001


def test_alternating_sequence_fails_runs_test() -> None:
    """An alternating sequence [0, 1, 0, 1, ...] has V_n = n (too many runs) and fails Runs test."""
    alternating = [0, 1] * 500  # 1000 bits
    # Monobit passes because exactly 500 zeros and 500 ones
    res_mono = monobit_frequency_test(alternating)
    assert res_mono.status == TestStatus.PASS

    # Runs test should detect rapid oscillation (V_n = 1000) and fail
    res_runs = runs_test(alternating)
    assert res_runs.status == TestStatus.FAIL
    assert res_runs.passed is False
    assert res_runs.p_value is not None
    assert res_runs.p_value < 1e-10
    assert res_runs.statistic == 1000.0


def test_clumped_runs_fail_runs_test() -> None:
    """A sequence with two huge blocks [0]*500 + [1]*500 has V_n = 2 (too few runs) and fails."""
    clumped = [0] * 500 + [1] * 500
    res_runs = runs_test(clumped)
    assert res_runs.status == TestStatus.FAIL
    assert res_runs.passed is False
    assert res_runs.p_value is not None
    assert res_runs.p_value < 1e-10
    assert res_runs.statistic == 2.0


def test_short_sequence_returns_not_applicable() -> None:
    """Sequences below NIST minimum (n < 100) return NOT_APPLICABLE rather than erroring."""
    short = [0, 1] * 20  # 40 bits
    res_mono = monobit_frequency_test(short)
    assert res_mono.status == TestStatus.NOT_APPLICABLE
    assert res_mono.p_value is None
    assert res_mono.passed is False
    assert "below NIST minimum" in (res_mono.error_message or "")

    res_block = block_frequency_test(short, block_size=20)
    assert res_block.status == TestStatus.NOT_APPLICABLE
    assert res_block.p_value is None

    res_runs = runs_test(short)
    assert res_runs.status == TestStatus.NOT_APPLICABLE
    assert res_runs.p_value is None


def test_block_frequency_parameter_constraints() -> None:
    """Block Frequency test rejects invalid M and N constraints per NIST SP 800-22."""
    bits = [0, 1] * 500  # 1000 bits

    # M < 20
    res_m_small = block_frequency_test(bits, block_size=10)
    assert res_m_small.status == TestStatus.NOT_APPLICABLE
    assert "M >= 20" in (res_m_small.error_message or "")

    # M <= 0.01 * n: for n=10000, 0.01*n = 100. If M=50, M <= 100 -> NOT_APPLICABLE
    long_bits = [0, 1] * 5000  # 10000 bits
    res_m_ratio = block_frequency_test(long_bits, block_size=50)
    assert res_m_ratio.status == TestStatus.NOT_APPLICABLE
    assert "M > 0.01*n" in (res_m_ratio.error_message or "")


# ==============================================================================
# D. Result Structure & Battery Tests
# ==============================================================================


def test_nist_test_result_structure() -> None:
    """NISTTestResult contains all required fields with consistent types."""
    bits = [0, 1] * 100
    res = monobit_frequency_test(bits, alpha=0.05)
    assert isinstance(res, NISTTestResult)
    assert res.test_name == "Frequency (Monobit) Test"
    assert isinstance(res.p_value, float)
    assert res.alpha == 0.05
    assert isinstance(res.status, TestStatus)
    assert isinstance(res.passed, bool)
    assert res.sequence_length == 200
    assert isinstance(res.statistic, float)
    assert isinstance(res.metadata, dict)


def test_run_nist_battery_structure() -> None:
    """run_nist_battery returns consolidated suite result with all 3 core tests."""
    bits = [0, 1] * 512  # 1024 bits
    suite_res = run_nist_battery(bits, block_size=128)
    assert isinstance(suite_res, NISTSuiteResult)
    assert suite_res.sequence_length == 1024
    assert len(suite_res.results) == 3
    test_names = {r.test_name for r in suite_res.results}
    assert test_names == {
        "Frequency (Monobit) Test",
        "Block Frequency Test",
        "Runs Test",
    }
    assert "total_tests" in suite_res.summary


def test_audit_exact_values_on_professor_datasets() -> None:
    """Audit test verifying exact mathematical outputs on the 3 professor datasets."""
    import math

    # 1024 dataset
    bits_1024 = parse_bit_csv(find_dataset_path(1024))
    res_m1024 = monobit_frequency_test(bits_1024)
    res_b1024 = block_frequency_test(bits_1024, block_size=128)
    res_r1024 = runs_test(bits_1024)

    assert math.isclose(res_m1024.p_value, 0.41650479, rel_tol=1e-5)
    assert res_m1024.status == TestStatus.PASS
    assert math.isclose(res_b1024.p_value, 0.22969892, rel_tol=1e-5)
    assert res_b1024.status == TestStatus.PASS
    assert math.isclose(res_r1024.p_value, 0.00428729, rel_tol=1e-5)
    assert res_r1024.status == TestStatus.FAIL

    # 2048 dataset
    bits_2048 = parse_bit_csv(find_dataset_path(2048))
    res_m2048 = monobit_frequency_test(bits_2048)
    res_b2048 = block_frequency_test(bits_2048, block_size=128)
    res_r2048 = runs_test(bits_2048)

    assert math.isclose(res_m2048.p_value, 0.23277434, rel_tol=1e-5)
    assert res_m2048.status == TestStatus.PASS
    assert math.isclose(res_b2048.p_value, 0.18707318, rel_tol=1e-5)
    assert res_b2048.status == TestStatus.PASS
    assert res_r2048.p_value < 1e-6
    assert res_r2048.status == TestStatus.FAIL

    # 3072 dataset
    bits_3072 = parse_bit_csv(find_dataset_path(3072))
    res_m3072 = monobit_frequency_test(bits_3072)
    res_b3072 = block_frequency_test(bits_3072, block_size=128)
    res_r3072 = runs_test(bits_3072)

    assert math.isclose(res_m3072.p_value, 0.40657214, rel_tol=1e-5)
    assert res_m3072.status == TestStatus.PASS
    assert math.isclose(res_b3072.p_value, 0.33905016, rel_tol=1e-5)
    assert res_b3072.status == TestStatus.PASS
    assert res_r3072.p_value < 1e-10
    assert res_r3072.status == TestStatus.FAIL

