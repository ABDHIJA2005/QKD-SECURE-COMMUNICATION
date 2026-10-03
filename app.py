"""Polished Streamlit presentation for the QKD Secure Communication demo."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import streamlit as st

from src.bb84 import (
    DEFAULT_QISKIT_TRANSMISSION_SIZE,
    SUPPORTED_TRANSMISSION_SIZES,
    BB84Simulation,
    BB84SimulationResult,
    QiskitBB84Simulation,
)
from src.crypto import derive_aes256_key
from src.file_crypto import FileDecryptionService, FileEncryptionService
from src.randomness import (
    DEFAULT_ALPHA,
    NISTSuiteResult,
    TestStatus,
    find_dataset_path,
    parse_bit_csv,
    run_nist_battery,
)


def _initialize_state() -> None:
    """Create only the short-lived state needed to continue the demo."""
    defaults = {
        "bb84_result": None,
        "application_key": None,
        "encrypted_data": None,
        "encrypted_filename": None,
        "decrypted_data": None,
        "decrypted_filename": None,
        "nist_suite_result": None,
        "nist_source_name": None,
        "nist_bit_count": None,
    }
    for name, value in defaults.items():
        st.session_state.setdefault(name, value)


def _render_styles() -> None:
    """Apply restrained academic styling without changing Streamlit behavior."""
    st.markdown(
        """
        <style>
        :root { --qkd-ink: #172033; --qkd-heading: #0f1f3d; --qkd-body: #334155;
          --qkd-muted: #526276; --qkd-border: #cbd5e1; --qkd-surface: #ffffff; }
        [data-testid="stAppViewContainer"] { background: #f6f8fb; color: var(--qkd-body); }
        [data-testid="stHeader"] { background: rgba(246, 248, 251, 0.96); }
        [data-testid="stSidebar"] { background: #e7edf4; border-right: 1px solid var(--qkd-border); }
        .block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 3rem; }
        h1, h2, h3, h4 { color: var(--qkd-heading) !important; letter-spacing: -0.01em; }
        [data-testid="stMarkdownContainer"] p, [data-testid="stCaptionContainer"] p,
        [data-testid="stText"] { color: var(--qkd-body); }
        [data-testid="stCaptionContainer"] p { color: var(--qkd-muted) !important; }
        [data-testid="stMetric"] { background: var(--qkd-surface); border: 1px solid var(--qkd-border);
          border-radius: 10px; padding: 0.8rem 1rem; box-shadow: 0 1px 2px rgba(15,23,42,.06); }
        [data-testid="stMetricLabel"] p, [data-testid="stMetricLabel"] div,
        [data-testid="stMetricLabel"] span { color: #3b4b61 !important; font-weight: 600 !important; }
        [data-testid="stMetricValue"] div, [data-testid="stMetricValue"] p,
        [data-testid="stMetricValue"] span { color: var(--qkd-heading) !important; font-weight: 700 !important; }
        [data-testid="stExpander"] { background: var(--qkd-surface); border: 1px solid var(--qkd-border); }
        [data-testid="stExpander"] summary p, [data-testid="stExpander"] summary span,
        [data-testid="stExpander"] [data-testid="stMarkdownContainer"] p { color: var(--qkd-heading) !important; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
        [data-testid="stSidebar"] label, [data-testid="stSidebar"] label p,
        [data-testid="stSidebar"] [data-testid="stWidgetLabel"] p { color: #1e293b !important; }
        [data-testid="stSidebar"] small, [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
          color: #334155 !important; }
        [data-testid="stSidebar"] input[data-testid="stNumberInputField"] {
          color: #f8fafc !important; -webkit-text-fill-color: #f8fafc !important; }
        [data-testid="stFileUploaderDropzone"] { background: var(--qkd-surface) !important;
          border: 1px dashed #94a3b8 !important; }
        [data-testid="stFileUploaderDropzone"] * { color: #334155 !important; }
        [data-testid="stFileUploaderDropzone"] button { background: #e2e8f0 !important;
          border: 1px solid #94a3b8 !important; color: #172033 !important; }
        [data-testid="stButton"] button { color: #172033 !important; font-weight: 600 !important;
          border-color: #94a3b8 !important; }
        [data-testid="stButton"] button[kind="primary"] { color: #ffffff !important;
          background: #1d4ed8 !important; border-color: #1d4ed8 !important; }
        [data-testid="stButton"] button:disabled { color: #526276 !important;
          background: #dce3eb !important; border-color: #b8c4d1 !important; opacity: 1 !important; }
        .qkd-pipeline { color: #40516a; font-size: 0.91rem; font-weight: 600; letter-spacing: .01em; }
        .qkd-subtitle { color: var(--qkd-muted); font-size: 1.05rem; margin-top: -0.5rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_header() -> None:
    with st.container(border=True):
        st.title("QKD Secure Communication")
        st.markdown(
            "<div class='qkd-subtitle'>A Qiskit quantum-circuit simulation of BB84 key-establishment "
            "and secure file communication on AerSimulator.</div>",
            unsafe_allow_html=True,
        )
        st.write("")
        pipeline = st.columns(7)
        steps = ["Random Bit Source", "BB84", "Basis Sifting", "QBER", "Security Decision", "HKDF", "AES-256-GCM"]
        for index, step in enumerate(steps):
            pipeline[index].markdown(f"<div class='qkd-pipeline'>{step}</div>", unsafe_allow_html=True)


def _render_sidebar() -> tuple[int, bool, float, str]:
    with st.sidebar:
        st.header("Simulation Settings")
        backend_choice = st.radio(
            "Simulation Engine",
            options=["Qiskit Quantum Circuit (Aer)", "Classical Educational Simulation"],
            index=0,
            help="Choose between real quantum circuit simulation via Qiskit Aer or the classical reference simulation.",
        )
        if backend_choice == "Qiskit Quantum Circuit (Aer)":
            transmission_bits = st.selectbox(
                "Transmission size:",
                options=list(SUPPORTED_TRANSMISSION_SIZES),
                index=SUPPORTED_TRANSMISSION_SIZES.index(DEFAULT_QISKIT_TRANSMISSION_SIZE),
                help="Manageable Qiskit transmission size: 1000, 2000, or 3000 qubits.",
            )
        else:
            transmission_bits = st.selectbox(
                "Transmission size (bits)",
                options=[1000, 2000, 3000, 10000],
                index=0,
                help="Transmission size for classical reference simulation.",
            )
        eve_enabled = st.toggle(
            "Eve: Enabled / Disabled",
            value=False,
            help="Enable the intercept-resend attacker.",
        )
        qber_threshold = st.number_input(
            "QBER threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.11,
            step=0.01,
            format="%.2f",
            help="QBER at or below this value may be accepted.",
        )
        st.caption("All values are generated by the underlying simulation; no results are hard-coded.")
    return int(transmission_bits), eve_enabled, float(qber_threshold), backend_choice



def _render_dashboard(result: BB84SimulationResult | None) -> None:
    st.subheader("Current Status")
    with st.container(border=True):
        if result is None:
            columns = st.columns(4)
            columns[0].metric("BB84 status", "Not run yet")
            columns[1].metric("QBER", "Not available")
            columns[2].metric("Security", "Not available")
            columns[3].metric("Application key", "Not available")
            st.caption("Run the BB84 simulation to populate the protocol dashboard.")
            return

        metadata = result.metadata
        security = metadata.security_decision
        columns = st.columns(4)
        columns[0].metric("Transmission bits", metadata.transmitted_bits)
        columns[1].metric("Matching bases", metadata.matching_basis_count)
        columns[2].metric("Sifted key length", metadata.sifted_key_length)
        columns[3].metric("Eve", "Enabled" if metadata.eve_enabled else "Disabled")
        columns = st.columns(4)
        columns[0].metric("QBER", metadata.qber_percentage)
        columns[1].metric("QBER threshold", f"{security.threshold:.2%}")
        columns[2].metric("Security", security.status.upper())
        columns[3].metric(
            "Application key", "Ready" if security.accepted else "Blocked"
        )


def _render_bb84_section(
    transmission_bits: int, eve_enabled: bool, qber_threshold: float, backend_choice: str = "Qiskit Quantum Circuit (Aer)"
) -> BB84SimulationResult | None:
    is_qiskit = "Qiskit" in backend_choice
    engine_name = "Qiskit Aer Quantum Circuit" if is_qiskit else "Classical Educational"
    st.header(f"1. BB84 Key Establishment ({engine_name})")
    if is_qiskit:
        st.caption(
            f"Quantum circuit simulation of {transmission_bits:,} qubits (|0>, |1>, |+>, |->) executed on Qiskit AerSimulator. "
            f"Eve is {'enabled' if eve_enabled else 'disabled'}."
        )
    else:
        st.caption(
            f"Classical educational simulation using {transmission_bits:,} transmission bits. "
            f"Eve is {'enabled' if eve_enabled else 'disabled'}."
        )
    if st.button("Run BB84 Simulation", type="primary"):
        try:
            if is_qiskit:
                simulation = QiskitBB84Simulation(
                    eve_enabled=eve_enabled, qber_threshold=qber_threshold
                )
            else:
                simulation = BB84Simulation(
                    eve_enabled=eve_enabled, qber_threshold=qber_threshold
                )
            result = simulation.run(transmission_bits)
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
            st.success(f"BB84 simulation completed successfully using {engine_name}.")
        except (TypeError, ValueError) as error:
            st.error(f"Simulation settings are invalid: {error}")
        except Exception:
            st.error("The BB84 simulation could not be completed.")
    return st.session_state.bb84_result



def _render_security_section(result: BB84SimulationResult | None) -> None:
    st.header("2. Security Analysis")
    if result is None:
        st.info("Run BB84 to calculate QBER and assess the key.")
        return

    metadata = result.metadata
    security = metadata.security_decision
    with st.container(border=True):
        columns = st.columns(4)
        columns[0].metric("QBER", metadata.qber_percentage)
        columns[1].metric("Threshold", f"{security.threshold:.2%}")
        columns[2].metric("Matching bases", metadata.matching_basis_count)
        columns[3].metric("Sifted key length", metadata.sifted_key_length)
        st.write(
            "QBER measures disagreement between the sifted Alice and Bob bits. "
            "Low/acceptable QBER permits key derivation; high QBER blocks it."
        )
        if security.accepted:
            st.success("Security decision: ACCEPTED — BB84 material may be used for key derivation.")
        else:
            st.error("Security decision: REJECTED — key derivation and encryption are blocked.")
        if metadata.eve_enabled:
            st.info(
                "Eve intercepts and resends states with randomly selected bases, "
                "which can introduce errors detected through QBER."
            )


def _render_key_section(result: BB84SimulationResult | None) -> None:
    st.header("3. Secure Key Derivation")
    with st.container(border=True):
        if result is None:
            st.info("Waiting for an accepted BB84 result.")
        elif result.metadata.security_decision.accepted:
            st.success("Application key ready — HKDF-SHA256 derived a 256-bit key.")
            st.caption("The key itself is never displayed.")
        else:
            st.warning("Key derivation blocked because the BB84 security check failed.")


def _run_encryption(uploaded_file, result: BB84SimulationResult, transmission_bits: int, qber_threshold: float):
    filename = _safe_upload_name(uploaded_file.name, "uploaded_file")
    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory) / filename
        temporary_path.write_bytes(uploaded_file.getvalue())
        service = FileEncryptionService(
            bb84_bit_count=transmission_bits, qber_threshold=qber_threshold
        )
        encryption_result = service.encrypt_file(
            temporary_path,
            eve_enabled=result.metadata.eve_enabled,
            bb84_result=result,
            output_directory=temporary_directory,
        )
        encrypted_data = (
            encryption_result.output_path.read_bytes()
            if encryption_result.success and encryption_result.output_path
            else None
        )
    return encryption_result, encrypted_data


def _run_decryption(uploaded_file, application_key: bytes):
    filename = _safe_upload_name(uploaded_file.name, "uploaded_file.enc")
    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory) / filename
        temporary_path.write_bytes(uploaded_file.getvalue())
        output_directory = Path(temporary_directory) / "decrypted"
        output_directory.mkdir()
        decryption_result = FileDecryptionService().decrypt_file(
            temporary_path, application_key, output_directory=output_directory
        )
        plaintext = (
            decryption_result.output_path.read_bytes()
            if decryption_result.success and decryption_result.output_path
            else None
        )
    return decryption_result, plaintext


def _safe_upload_name(name: str, fallback: str) -> str:
    candidate = Path(name.replace("\\", "/")).name
    return candidate if candidate not in {"", ".", ".."} else fallback


def _render_encryption_section(
    result: BB84SimulationResult | None, transmission_bits: int, qber_threshold: float
) -> None:
    st.header("4. File Encryption")
    with st.container(border=True):
        st.caption("Upload any file; the accepted BB84 result gates the existing AES-256-GCM service.")
        uploaded_file = st.file_uploader("Choose a file to encrypt", key="encryption_upload")
        if uploaded_file is not None:
            st.write(f"Selected: `{uploaded_file.name}` · {len(uploaded_file.getvalue()):,} bytes")
        can_encrypt = (
            result is not None
            and result.metadata.security_decision.accepted
            and st.session_state.application_key is not None
        )
        if result is not None and not result.metadata.security_decision.accepted:
            st.warning("Encryption is unavailable while the security decision is rejected.")
        if st.button("Encrypt File", disabled=not can_encrypt):
            if uploaded_file is None:
                st.error("Select a file before encryption.")
            else:
                try:
                    encryption_result, encrypted_data = _run_encryption(
                        uploaded_file, result, transmission_bits, qber_threshold
                    )
                    if encryption_result.success and encrypted_data is not None:
                        st.session_state.encrypted_data = encrypted_data
                        st.session_state.encrypted_filename = encryption_result.output_filename
                        st.success("File encrypted successfully using AES-256-GCM.")
                        st.caption(
                            f"Original: {encryption_result.input_filename} ({encryption_result.input_file_size:,} bytes) · "
                            f"Encrypted: {encryption_result.output_filename} ({encryption_result.output_file_size:,} bytes)"
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


def _render_decryption_section() -> None:
    st.header("5. File Decryption")
    with st.container(border=True):
        st.caption("Encrypted .enc file → receiver upload → authenticated AES-256-GCM decryption → restored plaintext")
        decrypted_upload = st.file_uploader(
            "Choose an encrypted .enc file", type=["enc"], key="decryption_upload"
        )
        if decrypted_upload is not None:
            st.write(f"Selected: `{decrypted_upload.name}` · {len(decrypted_upload.getvalue()):,} bytes")
        has_key = st.session_state.application_key is not None
        if not has_key:
            st.info("Run an accepted BB84 simulation before decrypting.")
        if st.button("Decrypt File", disabled=decrypted_upload is None or not has_key):
            try:
                decryption_result, plaintext = _run_decryption(
                    decrypted_upload, st.session_state.application_key
                )
                if decryption_result.success and plaintext is not None:
                    st.session_state.decrypted_data = plaintext
                    st.session_state.decrypted_filename = decryption_result.output_filename
                    st.success("File decrypted and authenticated successfully.")
                    st.caption(
                        f"Restored: {decryption_result.output_filename} ({decryption_result.output_file_size:,} bytes)"
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


def _render_nist_section(result: BB84SimulationResult | None) -> None:
    st.header("6. NIST SP 800-22 Randomness Analysis")
    with st.container(border=True):
        st.caption(
            "Statistical evaluation of bitstream randomness (Frequency, Block Frequency, and Runs tests). "
            "Note: This analysis evaluates bit distribution only and is strictly independent of QKD security."
        )

        dataset_options = [
            "Professor Dataset (1024 bits)",
            "Professor Dataset (2048 bits)",
            "Professor Dataset (3072 bits)",
            "Alice's Raw Simulation Bits (Current Run)",
        ]

        selected_dataset = st.selectbox(
            "Select Bitstream Source:",
            options=dataset_options,
            index=0,
            help="Choose between professor-provided static CSV datasets or Alice's actual raw bits from the active simulation run.",
        )

        is_alice_run = selected_dataset == "Alice's Raw Simulation Bits (Current Run)"

        if is_alice_run and result is None:
            st.info(
                "No BB84 simulation has been executed yet. Run the BB84 simulation above "
                "to generate Alice's raw bits, or select a Professor Dataset."
            )

        col_btn, _ = st.columns([1, 3])
        with col_btn:
            run_disabled = is_alice_run and result is None
            run_analysis = st.button("Run NIST Analysis", disabled=run_disabled)

        if run_analysis:
            try:
                if selected_dataset == "Professor Dataset (1024 bits)":
                    path = find_dataset_path(1024)
                    bits = parse_bit_csv(path, expected_count=1024)
                    label = "Professor Dataset (1024 bits)"
                elif selected_dataset == "Professor Dataset (2048 bits)":
                    path = find_dataset_path(2048)
                    bits = parse_bit_csv(path, expected_count=2048)
                    label = "Professor Dataset (2048 bits)"
                elif selected_dataset == "Professor Dataset (3072 bits)":
                    path = find_dataset_path(3072)
                    bits = parse_bit_csv(path, expected_count=3072)
                    label = "Professor Dataset (3072 bits)"
                else:
                    if result is None:
                        st.error("No simulation run available. Run BB84 first.")
                        return
                    bits = result.alice_bits
                    label = f"Alice's Raw Simulation Bits (Current Run — {len(bits):,} bits)"

                suite_result = run_nist_battery(bits, alpha=DEFAULT_ALPHA, block_size=128)
                st.session_state.nist_suite_result = suite_result
                st.session_state.nist_source_name = label
                st.session_state.nist_bit_count = len(bits)
            except Exception as e:
                st.error(f"Failed to load or analyze dataset: {e}")

        # Display Results
        suite: NISTSuiteResult | None = st.session_state.nist_suite_result
        if suite is not None:
            st.write("")
            st.subheader(f"Results for: {st.session_state.nist_source_name}")
            st.caption(
                f"Evaluated sequence length: {st.session_state.nist_bit_count:,} bits | "
                f"Significance level α = {DEFAULT_ALPHA}"
            )

            table_rows = []
            for test in suite.results:
                stat_str = f"{test.statistic:.4f}" if test.statistic is not None else "N/A"
                if test.test_name == "Runs Test" and test.statistic is not None:
                    stat_str = f"{int(test.statistic)}"
                p_str = f"{test.p_value:.6f}" if test.p_value is not None else "N/A"
                if test.p_value is not None and test.p_value < 1e-6:
                    p_str = f"{test.p_value:.2e}"

                if test.status == TestStatus.PASS:
                    status_badge = "✅ PASS"
                elif test.status == TestStatus.FAIL:
                    status_badge = "❌ FAIL"
                else:
                    status_badge = "⚠️ NOT APPLICABLE"

                table_rows.append(
                    {
                        "Test": test.test_name,
                        "Statistic": stat_str,
                        "P-value": p_str,
                        "Alpha (α)": f"{test.alpha:.2f}",
                        "Result": status_badge,
                    }
                )

            st.table(table_rows)

            # Educational Interpretation (Task 5)
            st.info(
                "NIST SP 800-22 evaluates statistical properties of a bitstream. "
                "Passing these tests does not prove that a sequence is truly random, "
                "quantum in origin, or cryptographically secure."
            )

            statuses = {r.test_name: r.status for r in suite.results}
            if (
                statuses.get("Frequency (Monobit) Test") == TestStatus.PASS
                and statuses.get("Block Frequency Test") == TestStatus.PASS
                and statuses.get("Runs Test") == TestStatus.FAIL
            ):
                st.warning(
                    "**Statistical Note:** The sequence has approximately balanced zero/one frequency "
                    "but exhibits fewer bit transitions than expected by the Runs test."
                )

        # Explicit Separation from QKD Security (Task 6)
        st.markdown("---")
        st.markdown("#### NIST Randomness Analysis ≠ QKD Security Decision")
        st.markdown(
            """
            * **NIST SP 800-22** evaluates statistical properties (balance, block frequency, transitions) of a single bitstream.
            * **QBER (Quantum Bit Error Rate)** evaluates disagreement between Alice and Bob after basis sifting, detecting eavesdropping or channel disturbance.
            * **QBER** remains the **sole gatekeeper** determining whether the QKD key is accepted or rejected.
            * **HKDF-SHA256** runs **only** after QBER acceptance (threshold ≤ 11%).
            * **AES-256-GCM** uses the derived key for application encryption.
            
            *Security Invariant:* A NIST FAIL does **not** block HKDF or AES when QBER is acceptable. A NIST PASS **never** overrides a high QBER rejection.
            """
        )


def _render_how_it_works() -> None:
    with st.expander("How the System Works"):
        st.markdown(
            "1. Random bits are generated by the current software random-bit source.\n"
            "2. Alice and Bob choose BB84 bases and Bob measures the transmitted states.\n"
            "3. Matching bases are retained through sifting.\n"
            "4. QBER is calculated and the security decision determines whether the material is acceptable.\n"
            "5. Accepted material is processed using HKDF-SHA256 to derive a 256-bit application key.\n"
            "6. AES-256-GCM encrypts the selected file, which can then be downloaded and decrypted."
        )
        st.info(
            "Eve's intercept-resend behavior introduces errors because she cannot predict Alice's basis choices. "
            "The active implementation simulates quantum state preparation and measurement circuits on Qiskit's AerSimulator backend. "
            "This is an educational quantum-circuit simulation running on a classical computer, not a physical quantum communication system."
        )


def main() -> None:
    st.set_page_config(page_title="QKD Secure Communication", page_icon="🔐", layout="wide")
    _initialize_state()
    _render_styles()
    transmission_bits, eve_enabled, qber_threshold, backend_choice = _render_sidebar()
    _render_header()
    dashboard_placeholder = st.empty()
    result = _render_bb84_section(transmission_bits, eve_enabled, qber_threshold, backend_choice)
    with dashboard_placeholder.container():
        _render_dashboard(result)
    _render_security_section(result)
    _render_key_section(result)
    _render_encryption_section(result, transmission_bits, qber_threshold)
    _render_decryption_section()
    _render_nist_section(result)
    _render_how_it_works()



if __name__ == "__main__":
    main()
