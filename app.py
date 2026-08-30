"""Streamlit UI for the QKD Secure Communication academic demonstration."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import streamlit as st

from src.bb84 import BB84Simulation, BB84SimulationResult
from src.crypto import derive_aes256_key
from src.file_crypto import FileDecryptionService, FileEncryptionService


def _initialize_state() -> None:
    defaults = {
        "bb84_result": None,
        "application_key": None,
        "encrypted_data": None,
        "encrypted_filename": None,
        "decrypted_data": None,
        "decrypted_filename": None,
    }
    for name, value in defaults.items():
        st.session_state.setdefault(name, value)


def _safe_upload_name(name: str, fallback: str) -> str:
    candidate = Path(name.replace("\\", "/")).name
    return candidate if candidate not in {"", ".", ".."} else fallback


def _run_encryption(
    uploaded_file,
    bb84_result: BB84SimulationResult,
    application_key: bytes,
    transmission_bits: int,
    qber_threshold: float,
):
    """Run the existing file service in an isolated temporary workspace."""
    filename = _safe_upload_name(uploaded_file.name, "uploaded_file")
    file_bytes = uploaded_file.getvalue()
    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory) / filename
        temporary_path.write_bytes(file_bytes)
        service = FileEncryptionService(
            bb84_bit_count=transmission_bits, qber_threshold=qber_threshold
        )
        result = service.encrypt_file(
            temporary_path,
            eve_enabled=bb84_result.metadata.eve_enabled,
            bb84_result=bb84_result,
            output_directory=temporary_directory,
        )
        encrypted_bytes = (
            result.output_path.read_bytes() if result.success and result.output_path else None
        )
    return result, encrypted_bytes


def _run_decryption(uploaded_file, application_key: bytes):
    """Run the existing decryption service in an isolated temporary workspace."""
    filename = _safe_upload_name(uploaded_file.name, "uploaded_file.enc")
    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory) / filename
        temporary_path.write_bytes(uploaded_file.getvalue())
        output_directory = Path(temporary_directory) / "decrypted"
        output_directory.mkdir()
        result = FileDecryptionService().decrypt_file(
            temporary_path, application_key, output_directory=output_directory
        )
        plaintext = (
            result.output_path.read_bytes() if result.success and result.output_path else None
        )
    return result, plaintext


def _display_protocol_metrics(result: BB84SimulationResult) -> None:
    metadata = result.metadata
    columns = st.columns(4)
    columns[0].metric("Transmitted bits", metadata.transmitted_bits)
    columns[1].metric("Matching bases", metadata.matching_basis_count)
    columns[2].metric("Sifted key length", metadata.sifted_key_length)
    columns[3].metric("Eve", "Enabled" if metadata.eve_enabled else "Disabled")


def main() -> None:
    st.set_page_config(page_title="QKD Secure Communication", page_icon="🔐")
    _initialize_state()

    st.title("QKD Secure Communication")
    st.caption(
        "BB84-based key establishment with QBER security checking and "
        "AES-256-GCM file encryption."
    )

    with st.sidebar:
        st.header("Simulation settings")
        transmission_bits = st.number_input(
            "Number of BB84 transmission bits",
            min_value=1,
            max_value=1_000_000,
            value=10_000,
            step=1_000,
        )
        eve_enabled = st.toggle("Eve: Enabled / Disabled", value=False)
        qber_threshold = st.number_input(
            "QBER threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.11,
            step=0.01,
            format="%.2f",
        )
        with st.expander("Information"):
            st.write(
                "Use Eve to demonstrate intercept-resend detection. A higher "
                "QBER than the threshold blocks key derivation and encryption."
            )

    st.info(
        "Random Bit Generation  →  BB84 Key Establishment  →  Basis Sifting  →  "
        "QBER Calculation  →  Security Decision  →  HKDF  →  AES-256-GCM"
    )

    st.header("1. BB84 Key Establishment")
    st.write(
        "Run the classical educational BB84 simulation using the configured "
        "transmission count and Eve setting. Secret bit sequences are kept private."
    )
    if st.button("Run BB84 Simulation", type="primary"):
        try:
            result = BB84Simulation(
                eve_enabled=eve_enabled, qber_threshold=float(qber_threshold)
            ).run(int(transmission_bits))
            st.session_state.bb84_result = result
            st.session_state.application_key = (
                derive_aes256_key(
                    result.sifted_key.alice_bits, result.metadata.security_decision
                )
                if result.metadata.security_decision.accepted
                else None
            )
            st.session_state.encrypted_data = None
            st.session_state.encrypted_filename = None
            st.session_state.decrypted_data = None
            st.session_state.decrypted_filename = None
            st.success("BB84 simulation completed.")
        except (TypeError, ValueError) as error:
            st.error(f"Simulation settings are invalid: {error}")
        except Exception:
            st.error("The BB84 simulation could not be completed.")

    result = st.session_state.bb84_result
    if result is not None:
        _display_protocol_metrics(result)

    st.header("2. Security Analysis")
    if result is None:
        st.info("Run the BB84 simulation to calculate QBER and assess security.")
    else:
        security = result.metadata.security_decision
        columns = st.columns(3)
        columns[0].metric("QBER", result.metadata.qber_percentage)
        columns[1].metric("Threshold", f"{security.threshold:.2%}")
        columns[2].metric("Decision", security.status.upper())
        st.write(
            "QBER measures disagreements between the sifted Alice and Bob bits. "
            "If it exceeds the configured threshold, encryption cannot proceed."
        )
        if security.accepted:
            st.success("Security decision: ACCEPTED")
        else:
            st.error("Security decision: REJECTED")
        if result.metadata.eve_enabled:
            st.info(
                "Eve intercepts and resends quantum states using randomly selected "
                "measurement bases. This introduces errors detected through QBER."
            )

    st.header("3. Secure Key Derivation")
    if result is None:
        st.info("An accepted BB84 result is required before deriving an application key.")
    elif result.metadata.security_decision.accepted:
        st.success("256-bit application key derived successfully.")
    else:
        st.warning("Key derivation blocked because the BB84 security check failed.")

    st.header("4. File Encryption")
    uploaded_file = st.file_uploader("Choose any file to encrypt", key="encryption_upload")
    if uploaded_file is not None:
        st.write(f"Selected: `{uploaded_file.name}` ({len(uploaded_file.getvalue()):,} bytes)")
    can_encrypt = (
        result is not None
        and result.metadata.security_decision.accepted
        and st.session_state.application_key is not None
    )
    if st.button("Encrypt File", disabled=not can_encrypt):
        if uploaded_file is None:
            st.error("Select a file before encryption.")
        else:
            try:
                encryption_result, encrypted_bytes = _run_encryption(
                    uploaded_file,
                    result,
                    st.session_state.application_key,
                    int(transmission_bits),
                    float(qber_threshold),
                )
                if encryption_result.success and encrypted_bytes is not None:
                    st.session_state.encrypted_data = encrypted_bytes
                    st.session_state.encrypted_filename = encryption_result.output_filename
                    st.success("File encrypted successfully using AES-256-GCM.")
                    st.write(
                        f"Original: {encryption_result.input_filename} "
                        f"({encryption_result.input_file_size:,} bytes)"
                    )
                    st.write(
                        f"Encrypted: {encryption_result.output_filename} "
                        f"({encryption_result.output_file_size:,} bytes)"
                    )
                else:
                    st.error("Encryption was blocked by the BB84 security decision.")
            except FileExistsError:
                st.error("An output file already exists; no file was overwritten.")
            except Exception:
                st.error("The file could not be encrypted.")

    if st.session_state.encrypted_data is not None:
        st.download_button(
            "Download encrypted .enc file",
            data=st.session_state.encrypted_data,
            file_name=st.session_state.encrypted_filename,
            mime="application/octet-stream",
            key="encrypted_download",
        )

    st.header("5. File Decryption")
    decrypted_upload = st.file_uploader(
        "Choose an encrypted .enc file", type=["enc"], key="decryption_upload"
    )
    if st.button(
        "Decrypt File",
        disabled=decrypted_upload is None or st.session_state.application_key is None,
    ):
        if decrypted_upload is None:
            st.error("Select an encrypted .enc file before decryption.")
        elif st.session_state.application_key is None:
            st.error("Run an accepted BB84 simulation before decryption.")
        else:
            try:
                decryption_result, plaintext = _run_decryption(
                    decrypted_upload, st.session_state.application_key
                )
                if decryption_result.success and plaintext is not None:
                    st.session_state.decrypted_data = plaintext
                    st.session_state.decrypted_filename = decryption_result.output_filename
                    st.success("File decrypted and authenticated successfully.")
                    st.write(
                        f"Restored: {decryption_result.output_filename} "
                        f"({decryption_result.output_file_size:,} bytes)"
                    )
                else:
                    st.session_state.decrypted_data = None
                    st.error(
                        "Decryption failed safely: "
                        + (decryption_result.error or "authentication failed")
                    )
            except FileExistsError:
                st.error("The restored filename already exists; no file was overwritten.")
            except Exception:
                st.error("The encrypted file could not be decrypted.")

    if st.session_state.decrypted_data is not None:
        st.download_button(
            "Download restored plaintext",
            data=st.session_state.decrypted_data,
            file_name=st.session_state.decrypted_filename,
            mime="application/octet-stream",
            key="decrypted_download",
        )

    with st.expander("How it works"):
        st.write(
            "1. Random bits and bases are generated.\n"
            "2. Alice and Bob perform the BB84 simulation.\n"
            "3. Matching bases are retained.\n"
            "4. QBER is calculated.\n"
            "5. High QBER causes the key to be rejected.\n"
            "6. Accepted BB84 material is processed with HKDF-SHA256.\n"
            "7. A 256-bit AES key is derived.\n"
            "8. AES-256-GCM encrypts the uploaded file.\n"
            "9. The authenticated encrypted file can be downloaded."
        )
        st.write(
            "Eve's intercept-resend attack introduces errors because Eve does not "
            "know the correct measurement basis. This is a classical educational "
            "simulation, not a physical quantum communication system."
        )


if __name__ == "__main__":
    main()
