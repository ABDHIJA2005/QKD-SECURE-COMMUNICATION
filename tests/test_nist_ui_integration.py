"""Tests for NIST SP 800-22 UI integration and non-interference with QKD security."""

from __future__ import annotations

import site
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# Ensure active interpreter's site-packages takes precedence over foreign venv paths in sys.path
for _site_pkg in site.getsitepackages():
    if _site_pkg in sys.path:
        sys.path.remove(_site_pkg)
        sys.path.insert(1, _site_pkg)

import pytest

from src.bb84 import (
    BB84SimulationResult,
    QiskitBB84Simulation,
)
from src.crypto import derive_aes256_key
from src.file_crypto import FileEncryptionService
from src.randomness import (
    DEFAULT_ALPHA,
    NISTSuiteResult,
    TestStatus,
    find_dataset_path,
    parse_bit_csv,
    run_nist_battery,
)
from src.security import (
    DEFAULT_QBER_THRESHOLD,
    SecurityDecision,
    assess_key_security,
)


# ==============================================================================
# 1-3. Professor Datasets Selection and Loading
# ==============================================================================


def test_professor_1024_dataset_selection_and_loading() -> None:
    """Professor 1024 dataset can be located and parsed into exactly 1024 bits."""
    path = find_dataset_path(1024)
    bits = parse_bit_csv(path, expected_count=1024)
    assert len(bits) == 1024
    assert all(b in (0, 1) for b in bits)


def test_professor_2048_dataset_selection_and_loading() -> None:
    """Professor 2048 dataset can be located and parsed into exactly 2048 bits."""
    path = find_dataset_path(2048)
    bits = parse_bit_csv(path, expected_count=2048)
    assert len(bits) == 2048
    assert all(b in (0, 1) for b in bits)


def test_professor_3072_dataset_selection_and_loading() -> None:
    """Professor 3072 dataset can be located and parsed into exactly 3072 bits."""
    path = find_dataset_path(3072)
    bits = parse_bit_csv(path, expected_count=3072)
    assert len(bits) == 3072
    assert all(b in (0, 1) for b in bits)


# ==============================================================================
# 4. NIST Battery Receives Correct Bit Count
# ==============================================================================


@pytest.mark.parametrize("size", [1024, 2048, 3072])
def test_nist_battery_receives_correct_bit_count(size: int) -> None:
    """NIST battery runs on the exact bit count of the selected dataset."""
    path = find_dataset_path(size)
    bits = parse_bit_csv(path, expected_count=size)
    suite = run_nist_battery(bits, alpha=DEFAULT_ALPHA, block_size=128)
    assert suite.sequence_length == size
    assert len(suite.results) == 3
    for test in suite.results:
        assert test.sequence_length == size


# ==============================================================================
# 5. Alice's Raw Simulation Bits from Qiskit BB84 Run
# ==============================================================================


def test_qiskit_alice_raw_bits_exposure_and_nist_analysis() -> None:
    """Alice's raw transmitted bits from a Qiskit BB84 run can be passed to NIST."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    result: BB84SimulationResult = sim.run(1000)

    # Verify both direct field and property accessor exist
    assert hasattr(result, "alice_bits")
    assert hasattr(result, "alice_raw_bits")
    assert result.alice_bits == result.alice_raw_bits
    assert len(result.alice_raw_bits) == 1000
    assert all(b in (0, 1) for b in result.alice_raw_bits)

    # Verify NIST battery runs cleanly on Alice's raw bits
    suite = run_nist_battery(result.alice_raw_bits, alpha=DEFAULT_ALPHA, block_size=128)
    assert suite.sequence_length == 1000
    assert len(suite.results) == 3


# ==============================================================================
# 6. NIST Result Does Not Alter QBER Security Decision
# ==============================================================================


def test_nist_result_does_not_alter_qber_security_decision() -> None:
    """Running NIST analysis on any bitstream has no impact on QBER or security decision."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    result = sim.run(1000)

    decision_before = result.metadata.security_decision
    qber_before = result.metadata.qber

    # Run NIST on a failing bitstream (e.g. Professor 1024 where Runs fails)
    prof_bits = parse_bit_csv(find_dataset_path(1024))
    suite_fail = run_nist_battery(prof_bits)
    assert not suite_fail.all_passed

    # Verify original QKD simulation decision and QBER are unaffected
    assert result.metadata.security_decision == decision_before
    assert result.metadata.security_decision.accepted is True
    assert result.metadata.qber == qber_before


# ==============================================================================
# 7. NIST FAIL Does Not Block HKDF/AES When QBER Accepts
# ==============================================================================


def test_nist_fail_does_not_block_hkdf_or_aes_when_qber_accepts() -> None:
    """When QBER is acceptable, key derivation and file encryption succeed even if NIST fails."""
    sim = QiskitBB84Simulation(eve_enabled=False)
    result = sim.run(1000)
    assert result.metadata.security_decision.accepted is True

    # Intentionally evaluate a dataset known to fail NIST (e.g., 1024 bits Runs test fails)
    prof_bits = parse_bit_csv(find_dataset_path(1024))
    nist_result = run_nist_battery(prof_bits)
    assert nist_result.all_passed is False

    # HKDF-SHA256 must still successfully derive key using QKD sifted material
    application_key = derive_aes256_key(
        result.sifted_key.alice_bits, result.metadata.security_decision
    )
    assert application_key is not None
    assert len(application_key) == 32

    # AES-256-GCM encryption service must succeed regardless of NIST status
    with TemporaryDirectory() as tmpdir:
        input_file = Path(tmpdir) / "test_doc.txt"
        input_file.write_text("Confidential Quantum Message", encoding="utf-8")

        service = FileEncryptionService(bb84_bit_count=1000, qber_threshold=0.11)
        enc_res = service.encrypt_file(
            input_file,
            eve_enabled=False,
            bb84_result=result,
            output_directory=tmpdir,
        )
        assert enc_res.success is True
        assert enc_res.output_path is not None
        assert enc_res.output_path.is_file()


# ==============================================================================
# 8. QBER Rejection Still Blocks Key Derivation Even if NIST Would Pass
# ==============================================================================


def test_qber_rejection_blocks_key_derivation_regardless_of_nist() -> None:
    """When QBER is above threshold (e.g. Eve intercept-resend), key derivation is strictly blocked."""
    # Simulate Eve attack -> high QBER (~25%)
    sim = QiskitBB84Simulation(eve_enabled=True, qber_threshold=0.11)
    result = sim.run(1000)

    assert result.metadata.qber > 0.11
    assert result.metadata.security_decision.accepted is False

    # Even if an input passes all NIST tests, key derivation MUST raise ValueError
    with pytest.raises(ValueError, match="Rejected BB84 key material cannot derive an application key"):
        derive_aes256_key(
            result.sifted_key.alice_bits, result.metadata.security_decision
        )

    # Encryption service must fail safely
    with TemporaryDirectory() as tmpdir:
        input_file = Path(tmpdir) / "test_doc.txt"
        input_file.write_text("Confidential Quantum Message", encoding="utf-8")

        service = FileEncryptionService(bb84_bit_count=1000, qber_threshold=0.11)
        enc_res = service.encrypt_file(
            input_file,
            eve_enabled=True,
            bb84_result=result,
            output_directory=tmpdir,
        )
        assert enc_res.success is False
        assert enc_res.output_path is None
