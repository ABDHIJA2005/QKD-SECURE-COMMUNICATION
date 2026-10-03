"""CSV parsing and validation for bitstream datasets."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Sequence

EXPECTED_HEADER: tuple[str, str] = ("bit_index", "bit")


def parse_bit_csv_text(
    content: str, *, expected_count: int | None = None
) -> tuple[int, ...]:
    """Parse and validate CSV bitstream content from a text string.

    Format expected:
        bit_index,bit
        0,0
        1,1
        ...

    Validation rules:
    - Header must be exactly 'bit_index,bit'.
    - Every row must contain exactly two fields.
    - bit_index must be strictly sequential starting at 0 (0, 1, 2, ..., N-1).
    - bit must be strictly '0' or '1'.
    - No missing values or empty rows allowed.
    - If expected_count is provided, total rows must match exactly.

    Raises:
        ValueError: If the header is missing/invalid, rows are malformed,
            indices are non-sequential, bits are non-binary, or count mismatches.
    """
    lines = content.strip().splitlines()
    if not lines:
        raise ValueError("CSV content is empty.")

    reader = csv.reader(io.StringIO(content))
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("CSV content is empty.") from None

    cleaned_header = tuple(col.strip() for col in header)
    if cleaned_header != EXPECTED_HEADER:
        raise ValueError(
            f"Invalid CSV header: expected {EXPECTED_HEADER}, got {cleaned_header}."
        )

    bits: list[int] = []
    expected_index = 0

    for row_number, row in enumerate(reader, start=2):
        if len(row) != 2:
            raise ValueError(
                f"Malformed row at line {row_number}: expected 2 columns, got {len(row)}: {row}."
            )

        raw_index, raw_bit = row[0].strip(), row[1].strip()

        if not raw_index:
            raise ValueError(f"Missing bit_index at line {row_number}.")
        if not raw_bit:
            raise ValueError(f"Missing bit value at line {row_number}.")

        try:
            index = int(raw_index)
        except ValueError:
            raise ValueError(
                f"Non-integer bit_index '{raw_index}' at line {row_number}."
            ) from None

        if index != expected_index:
            raise ValueError(
                f"Non-sequential bit_index at line {row_number}: expected {expected_index}, got {index}."
            )

        if raw_bit not in ("0", "1"):
            raise ValueError(
                f"Non-binary bit value '{raw_bit}' at line {row_number}: must be 0 or 1."
            )

        bits.append(int(raw_bit))
        expected_index += 1

    if not bits:
        raise ValueError("CSV contains header but no bit data rows.")

    if expected_count is not None and len(bits) != expected_count:
        raise ValueError(
            f"Expected {expected_count} bits, but parsed {len(bits)} bits."
        )

    return tuple(bits)


def parse_bit_csv(
    file_path: str | Path, *, expected_count: int | None = None
) -> tuple[int, ...]:
    """Read, parse, and validate a CSV bitstream file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file contents are invalid or malformed.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Bitstream CSV file not found: {path.resolve()}")

    content = path.read_text(encoding="utf-8")
    return parse_bit_csv_text(content, expected_count=expected_count)


def find_dataset_path(identifier: str | int) -> Path:
    """Resolve a dataset identifier (filename or bit count like 1024) to a local Path.

    Looks in standard locations:
    1. Direct path if it exists
    2. OneDrive Desktop directory
    3. Project data/input directory
    4. Current workspace root

    Raises:
        FileNotFoundError: If the file cannot be located.
    """
    if isinstance(identifier, int) or (
        isinstance(identifier, str) and identifier.isdigit()
    ):
        filename = f"dwe_bits_nonoverlap_{identifier}.csv"
    else:
        filename = str(identifier)
        if not filename.endswith(".csv"):
            filename = f"{filename}.csv"

    candidate_dirs = [
        Path.cwd(),
        Path.cwd() / "data" / "input",
        Path.cwd() / "data",
        Path("C:/Users/abdhi/OneDrive/Desktop"),
        Path.home() / "OneDrive" / "Desktop",
        Path.home() / "Desktop",
    ]

    direct = Path(filename)
    if direct.is_file():
        return direct.resolve()

    for directory in candidate_dirs:
        candidate = directory / filename
        if candidate.is_file():
            return candidate.resolve()

    raise FileNotFoundError(
        f"Could not locate dataset '{filename}' in candidate locations."
    )
