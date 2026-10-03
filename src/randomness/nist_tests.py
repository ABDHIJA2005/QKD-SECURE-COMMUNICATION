"""NIST SP 800-22 Revision 1a statistical randomness tests.

Implements core tests recommended for sequence lengths >= 100 bits:
1. Frequency (Monobit) Test (Section 2.1)
2. Frequency Test within a Block (Block Frequency) (Section 2.2)
3. Runs Test (Section 2.3)
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from scipy.special import gammaincc

from .models import DEFAULT_ALPHA, NISTSuiteResult, NISTTestResult, TestStatus

# Minimum sequence length specified across NIST SP 800-22 tests
MIN_MONOBIT_N: int = 100
MIN_BLOCK_FREQUENCY_N: int = 100
MIN_RUNS_N: int = 100


def validate_bit_sequence(bits: Sequence[Any]) -> tuple[int, ...]:
    """Validate that the input is a non-empty sequence of binary integers (0 or 1).

    Raises:
        TypeError: If elements are not integers or are booleans.
        ValueError: If sequence is empty or elements are not in {0, 1}.
    """
    if not isinstance(bits, Sequence) or isinstance(bits, (str, bytes)):
        raise TypeError(
            f"Bit sequence must be a Python Sequence, got {type(bits).__name__}."
        )

    if len(bits) == 0:
        raise ValueError("Bit sequence cannot be empty.")

    validated: list[int] = []
    for index, bit in enumerate(bits):
        # In Python, bool is a subclass of int (isinstance(True, int) is True), so check type explicitly
        if type(bit) is bool or not isinstance(bit, int):
            raise TypeError(
                f"Element at index {index} must be an integer (0 or 1), got {type(bit).__name__}: {bit!r}."
            )
        if bit not in (0, 1):
            raise ValueError(
                f"Element at index {index} must be 0 or 1, got {bit}."
            )
        validated.append(bit)

    return tuple(validated)


def monobit_frequency_test(
    bits: Sequence[int], *, alpha: float = DEFAULT_ALPHA
) -> NISTTestResult:
    """Execute the NIST SP 800-22 Rev 1a Frequency (Monobit) Test (Section 2.1).

    Focus: Proportion of zeroes and ones in the entire sequence.
    Condition: n >= 100 bits.

    Returns:
        NISTTestResult with p_value, test statistic, and pass/fail decision.
    """
    validated = validate_bit_sequence(bits)
    n = len(validated)

    if n < MIN_MONOBIT_N:
        return NISTTestResult(
            test_name="Frequency (Monobit) Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"min_n_required": MIN_MONOBIT_N},
            error_message=(
                f"Sequence length n={n} is below NIST minimum requirement of {MIN_MONOBIT_N} bits."
            ),
        )

    # Convert 0 -> -1, 1 -> +1
    s_n = sum(2 * b - 1 for b in validated)
    s_obs = abs(s_n) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2.0))

    passed = p_value >= alpha
    status = TestStatus.PASS if passed else TestStatus.FAIL

    return NISTTestResult(
        test_name="Frequency (Monobit) Test",
        p_value=p_value,
        alpha=alpha,
        status=status,
        passed=passed,
        sequence_length=n,
        statistic=s_obs,
        metadata={
            "s_n": s_n,
            "s_obs": s_obs,
            "zeros": validated.count(0),
            "ones": validated.count(1),
            "proportion_ones": validated.count(1) / n,
        },
    )


def block_frequency_test(
    bits: Sequence[int],
    *,
    block_size: int = 128,
    alpha: float = DEFAULT_ALPHA,
) -> NISTTestResult:
    """Execute the NIST SP 800-22 Rev 1a Block Frequency Test (Section 2.2).

    Focus: Proportion of ones within M-bit blocks.
    NIST Constraints (Section 2.2.7):
    - n >= 100
    - M >= 20
    - M > 0.01 * n
    - N = floor(n / M) < 100
    - N >= 1

    Returns:
        NISTTestResult with chi-square statistic, p-value, and pass/fail decision.
    """
    validated = validate_bit_sequence(bits)
    n = len(validated)
    m = block_size

    if n < MIN_BLOCK_FREQUENCY_N:
        return NISTTestResult(
            test_name="Block Frequency Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"block_size": m, "min_n_required": MIN_BLOCK_FREQUENCY_N},
            error_message=(
                f"Sequence length n={n} is below NIST minimum requirement of {MIN_BLOCK_FREQUENCY_N} bits."
            ),
        )

    if m < 20:
        return NISTTestResult(
            test_name="Block Frequency Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"block_size": m},
            error_message=f"Block size M={m} is invalid: NIST requires M >= 20.",
        )

    if m <= 0.01 * n:
        return NISTTestResult(
            test_name="Block Frequency Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"block_size": m, "min_m_threshold": 0.01 * n},
            error_message=(
                f"Block size M={m} is too small for sequence length n={n}: NIST requires M > 0.01*n ({0.01*n:.2f})."
            ),
        )

    num_blocks = n // m
    if num_blocks >= 100:
        return NISTTestResult(
            test_name="Block Frequency Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"block_size": m, "num_blocks": num_blocks},
            error_message=(
                f"Number of blocks N={num_blocks} exceeds NIST limit (requires N < 100)."
            ),
        )

    if num_blocks < 1:
        return NISTTestResult(
            test_name="Block Frequency Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"block_size": m, "num_blocks": num_blocks},
            error_message="Sequence is shorter than one block (N < 1).",
        )

    # Compute block proportions and chi-square statistic
    chi_squared = 0.0
    block_proportions: list[float] = []

    for i in range(num_blocks):
        block = validated[i * m : (i + 1) * m]
        pi_i = sum(block) / m
        block_proportions.append(pi_i)
        chi_squared += (pi_i - 0.5) ** 2

    chi_squared *= 4.0 * m
    degrees_of_freedom = num_blocks / 2.0
    p_value = float(gammaincc(degrees_of_freedom, chi_squared / 2.0))

    passed = p_value >= alpha
    status = TestStatus.PASS if passed else TestStatus.FAIL

    return NISTTestResult(
        test_name="Block Frequency Test",
        p_value=p_value,
        alpha=alpha,
        status=status,
        passed=passed,
        sequence_length=n,
        statistic=chi_squared,
        metadata={
            "block_size": m,
            "num_blocks": num_blocks,
            "discarded_bits": n - (num_blocks * m),
            "chi_squared": chi_squared,
            "min_block_proportion": min(block_proportions),
            "max_block_proportion": max(block_proportions),
        },
    )


def runs_test(
    bits: Sequence[int], *, alpha: float = DEFAULT_ALPHA
) -> NISTTestResult:
    """Execute the NIST SP 800-22 Rev 1a Runs Test (Section 2.3).

    Focus: Total number of runs (uninterrupted sequences of identical bits).
    Conditions:
    - n >= 100
    - Precondition check (Section 2.3.4):
      tau = 2 / sqrt(n). If |pi - 0.5| >= tau, the test need not be run and p-value is set to 0.0.

    Returns:
        NISTTestResult with V_n observed, p-value, and pass/fail decision.
    """
    validated = validate_bit_sequence(bits)
    n = len(validated)

    if n < MIN_RUNS_N:
        return NISTTestResult(
            test_name="Runs Test",
            p_value=None,
            alpha=alpha,
            status=TestStatus.NOT_APPLICABLE,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={"min_n_required": MIN_RUNS_N},
            error_message=(
                f"Sequence length n={n} is below NIST minimum requirement of {MIN_RUNS_N} bits."
            ),
        )

    pi = sum(validated) / n
    tau = 2.0 / math.sqrt(n)

    # Prerequisite check: Frequency Monobit prerequisite
    if abs(pi - 0.5) >= tau:
        return NISTTestResult(
            test_name="Runs Test",
            p_value=0.0,
            alpha=alpha,
            status=TestStatus.FAIL,
            passed=False,
            sequence_length=n,
            statistic=None,
            metadata={
                "pi": pi,
                "tau": tau,
                "prerequisite_passed": False,
            },
            error_message=(
                f"Runs test prerequisite failed: |pi - 0.5| = {abs(pi - 0.5):.6f} >= tau = {tau:.6f}."
            ),
        )

    # Compute observed runs V_n(obs)
    v_n_obs = 1 + sum(
        1 for i in range(n - 1) if validated[i] != validated[i + 1]
    )

    expected_runs = 2.0 * n * pi * (1.0 - pi)
    # NIST SP 800-22 Rev 1a Section 2.3.4 erfc denominator: 2 * sqrt(2n) * pi * (1 - pi)
    erfc_denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    erfc_argument = abs(v_n_obs - expected_runs) / erfc_denominator
    p_value = math.erfc(erfc_argument)
    # Corresponding standard normal z-score: z = erfc_argument * sqrt(2)
    z_score = erfc_argument * math.sqrt(2.0)

    passed = p_value >= alpha
    status = TestStatus.PASS if passed else TestStatus.FAIL

    return NISTTestResult(
        test_name="Runs Test",
        p_value=p_value,
        alpha=alpha,
        status=status,
        passed=passed,
        sequence_length=n,
        statistic=float(v_n_obs),
        metadata={
            "pi": pi,
            "tau": tau,
            "prerequisite_passed": True,
            "v_n_obs": v_n_obs,
            "expected_runs": expected_runs,
            "erfc_denominator": erfc_denominator,
            "erfc_argument": erfc_argument,
            "z_score": z_score,
            "test_statistic": erfc_argument,
        },
    )


def run_nist_battery(
    bits: Sequence[int],
    *,
    alpha: float = DEFAULT_ALPHA,
    block_size: int = 128,
) -> NISTSuiteResult:
    """Run the core NIST SP 800-22 test battery on a bit sequence."""
    validated = validate_bit_sequence(bits)
    results = (
        monobit_frequency_test(validated, alpha=alpha),
        block_frequency_test(validated, block_size=block_size, alpha=alpha),
        runs_test(validated, alpha=alpha),
    )

    applicable_results = [
        r for r in results if r.status != TestStatus.NOT_APPLICABLE
    ]
    all_passed = (
        len(applicable_results) > 0
        and all(r.status == TestStatus.PASS for r in applicable_results)
    )

    summary = {
        "total_tests": len(results),
        "passed_tests": sum(1 for r in results if r.status == TestStatus.PASS),
        "failed_tests": sum(1 for r in results if r.status == TestStatus.FAIL),
        "not_applicable": sum(
            1 for r in results if r.status == TestStatus.NOT_APPLICABLE
        ),
    }

    return NISTSuiteResult(
        sequence_length=len(validated),
        results=results,
        all_passed=all_passed,
        summary=summary,
    )
