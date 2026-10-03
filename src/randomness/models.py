"""Data models for NIST SP 800-22 randomness testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

DEFAULT_ALPHA: float = 0.01


class TestStatus(str, Enum):
    """Execution status for a statistical randomness test."""

    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class NISTTestResult:
    """Structured result of an individual NIST statistical test.

    Attributes:
        test_name: Canonical name of the test.
        p_value: Computed asymptotic P-value (None if NOT_APPLICABLE).
        alpha: Significance level threshold (default 0.01).
        status: PASS, FAIL, or NOT_APPLICABLE.
        passed: True if status is PASS, False otherwise.
        sequence_length: Number of bits in the tested input sequence.
        statistic: Primary test statistic (e.g. s_obs, chi_sq, V_n).
        metadata: Test-specific parameters and intermediate calculations.
        error_message: Reason if test could not be evaluated or precondition failed.
    """

    __test__ = False
    test_name: str
    p_value: float | None
    alpha: float
    status: TestStatus
    passed: bool
    sequence_length: int
    statistic: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None


@dataclass(frozen=True)
class NISTSuiteResult:
    """Consolidated result for a battery of NIST statistical tests.

    Attributes:
        sequence_length: Total number of bits evaluated.
        results: Tuple of individual NISTTestResult objects.
        all_passed: True if every applicable test passed.
        summary: Overview dictionary of counts and outcomes.
    """

    sequence_length: int
    results: tuple[NISTTestResult, ...]
    all_passed: bool
    summary: dict[str, Any] = field(default_factory=dict)
