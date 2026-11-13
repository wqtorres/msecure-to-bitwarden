"""Reader for mSecure 6/7 CSV exports.

mSecure CSV layout (the first line is a banner and is discarded):
    column 1  : Title|ID
    column 2  : record type (Login, Credit Card, Secure Note, ...)
    column 3  : tags, comma separated
    column 4  : notes (a line break is stored as a real line break immediately
                followed by a literal backslash-n at the start of the next
                physical line; the value is NOT enclosed in quotes)
    column 5+ : Field name|Field type|Field value
                (fields whose value is empty are discarded)
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ============================================================================
# mSecure definitions
# ============================================================================

# Every record type mSecure 6/7 can produce. Used to recognise the beginning of
# a new record in the file.
MSECURE_RECORD_TYPES = [
    "Login", "Credit Card", "Secure Note", "Bank Account", "Birthdays",
    "Calling Card", "Clothes Size", "Combination", "Drivers License",
    "Email Account", "Frequent Flyer", "Identity", "Insurance Info",
    "Membership", "Outdoor License", "Passport", "Prescription",
    "Registration Code", "Reward Program", "Router Settings",
    "Social Security", "Software License", "Type", "Vehicle Info",
    "Voice Mail",
]

# mSecure field type codes that the converter treats specially
# (the other codes are simply copied as plain text custom fields)
MSECURE_FIELD_URL = 2
MSECURE_FIELD_USERNAME = 7
MSECURE_FIELD_PASSWORD = 8
MSECURE_FIELD_SENSITIVE_NUMBER = 9
MSECURE_FIELD_MONTH_YEAR = 11
MSECURE_FIELD_CREDIT_CARD_NUMBER = 12
MSECURE_FIELD_ONE_TIME_PASSWORD = 13

# mSecure field types whose values must be hidden (masked) in Bitwarden
MSECURE_FIELD_TYPES_TO_HIDE = {
    MSECURE_FIELD_PASSWORD,
    MSECURE_FIELD_SENSITIVE_NUMBER,
    MSECURE_FIELD_CREDIT_CARD_NUMBER,
    MSECURE_FIELD_ONE_TIME_PASSWORD,
}

# ============================================================================
# Record detection patterns
# ============================================================================

# A private-use Unicode character used as a temporary stand-in for line breaks.
# The csv module cannot handle raw line breaks inside unquoted values, so every
# line break is swapped for this character before parsing and swapped back after.
LINE_BREAK_PLACEHOLDER = "\ue000"

# Regex for the first column ("Title|ID"). The title is either:
#   - quoted (when it contains commas):  "My, title|123"
#   - unquoted (no commas inside):       My title|123
TITLE_COLUMN_PATTERN = r'(?:"(?:[^"]|"")*\|\d+"|[^,]*\|\d+)'

# All known record types joined with "|" for use inside a regex.
# Longest names first so "Credit Card" is tried before any shorter prefix.
KNOWN_RECORD_TYPES_PATTERN = "|".join(
    re.escape(record_type)
    for record_type in sorted(MSECURE_RECORD_TYPES, key=len, reverse=True)
)

# Strict start-of-record test: "Title|123,<known type>,"
# A line matching this is certainly the beginning of a new record.
STRICT_RECORD_START_PATTERN = re.compile(
    rf'^{TITLE_COLUMN_PATTERN},"?(?:{KNOWN_RECORD_TYPES_PATTERN})"?,'
)

# Loose start-of-record test: "Title|123,"
# Also matches record types that newer mSecure versions may add. It is only
# applied to lines that do NOT begin with a literal backslash-n, because
# those are always continuation lines of the previous record.
LOOSE_RECORD_START_PATTERN = re.compile(rf"^{TITLE_COLUMN_PATTERN},")

# Splits a record-specific column into: name | numeric type | value.
# The name is matched lazily so pipes inside the value (e.g. in passwords)
# are kept as part of the value.
FIELD_COLUMN_PATTERN = re.compile(r"^(.*?)\|(\d+)\|(.*)$", re.DOTALL)


# ============================================================================
# Data containers
# ============================================================================

@dataclass
class MSecureField:
    """One record-specific field: 'Field name|Field type|Field value'."""
    name: str
    field_type: int
    value: str


@dataclass
class MSecureRecord:
    """One fully parsed mSecure record (one logical row of the CSV)."""
    title: str
    record_type: str
    tags: list[str]
    notes: str
    fields: list[MSecureField]


# ============================================================================
# Splitting the file into records
# ============================================================================

def split_into_physical_lines(file_text: str) -> list[str]:
    """Split text on CRLF, LF or CR only.

    str.splitlines() is deliberately avoided because it also splits on other
    characters (\\x0b, \\x0c, \\u2028, ...) that may legitimately appear in data.
    """
    return re.split(r"\r\n|\n|\r", file_text)


def group_lines_into_records(physical_lines: list[str]) -> list[list[str]]:
    """Group physical lines into logical records.

    Notes and field values may contain line breaks and are not quoted, so one
    record can span several physical lines. mSecure writes each line break as
    a real line break followed by a literal backslash-n, so every continuation
    line BEGINS with a literal backslash-n. A line that does not begin with it
    and looks like 'Title|ID,<Type>,...' starts a new record.
    """
    # Discard the banner line ("mSecure6 CSV export file") unless it happens
    # to look like a real record.
    if physical_lines and not STRICT_RECORD_START_PATTERN.match(physical_lines[0]):
        physical_lines = physical_lines[1:]

    all_records: list[list[str]] = []
    current_record_lines: list[str] = []

    for line in physical_lines:
        # A line starting with a literal backslash-n continues the value that
        # was being written on the previous line.
        is_continuation_line = line.startswith("\\n")

        # Decide whether this line begins a new record.
        looks_like_new_record = not is_continuation_line and bool(
            STRICT_RECORD_START_PATTERN.match(line)
            or LOOSE_RECORD_START_PATTERN.match(line)
        )
        if current_record_lines and looks_like_new_record:
            all_records.append(current_record_lines)  # close the previous record
            current_record_lines = []

        # Ignore blank lines sitting between two records.
        if not current_record_lines and not line.strip():
            continue

        current_record_lines.append(line)

    if current_record_lines:
        all_records.append(current_record_lines)  # don't forget the last record

    # Drop trailing blank lines that do not belong to any record's content.
    for record_lines in all_records:
        while record_lines and not record_lines[-1].strip():
            record_lines.pop()

    return [record_lines for record_lines in all_records if record_lines]


# ============================================================================
# Parsing a single record
# ============================================================================

def parse_record(record_lines: list[str]) -> MSecureRecord | None:
    """Turn the physical lines of one record into an MSecureRecord.

    Returns None if the record cannot be parsed.
    """
    # mSecure writes each line break as a real line break followed by a literal
    # backslash-n at the start of the next physical line. Rebuild the record as
    # ONE line: remove that literal "\n" marker and put a placeholder character
    # where the line break was. After the csv module has split the columns, the
    # placeholder becomes a real line break again, and json.dumps writes it as
    # the "\n" escape sequence, which is how JSON represents a line break.
    record_text = record_lines[0]
    for continuation_line in record_lines[1:]:
        if continuation_line.startswith("\\n"):
            continuation_line = continuation_line[2:]  # drop the "\n" marker
        record_text += LINE_BREAK_PLACEHOLDER + continuation_line

    # The text is now a single line, so the csv module can split the columns
    # (it handles quoted values that contain commas for us).
    try:
        columns = next(csv.reader([record_text]))
    except (csv.Error, StopIteration):
        return None

    # Restore the real line breaks inside every column.
    columns = [column.replace(LINE_BREAK_PLACEHOLDER, "\n") for column in columns]
    if not columns or not columns[0].strip():
        return None

    # Column 1: "Title|ID" -> keep only the title (ID is not needed by Bitwarden).
    title_before_pipe, pipe_found, record_id = columns[0].rpartition("|")
    if pipe_found and record_id.strip().isdigit():
        title = title_before_pipe
    else:
        title = columns[0]

    # Column 2: record type.
    record_type = columns[1].strip() if len(columns) > 1 else "Secure Note"

    # Column 3: comma-separated tags.
    tags = (
        [tag.strip() for tag in columns[2].split(",") if tag.strip()]
        if len(columns) > 2
        else []
    )

    # Column 4: notes (surrounding line breaks removed).
    notes = columns[3].strip("\n") if len(columns) > 3 else ""

    # Columns 5+: record-specific fields in the form name|type|value.
    fields: list[MSecureField] = []
    for raw_field in columns[4:]:
        if not raw_field:
            continue  # empty column, nothing to import
        field_match = FIELD_COLUMN_PATTERN.match(raw_field)
        if field_match:
            field_value = field_match.group(3)
            if not field_value.strip():
                continue  # the field has a name but no value: discard it
            fields.append(
                MSecureField(
                    name=field_match.group(1),
                    field_type=int(field_match.group(2)),
                    value=field_value,
                )
            )
        else:
            # Unexpected format: keep the data instead of losing it.
            fields.append(MSecureField(name="Field", field_type=0, value=raw_field))

    return MSecureRecord(
        title=title.strip() or "(untitled)",
        record_type=record_type,
        tags=tags,
        notes=notes,
        fields=fields,
    )


# ============================================================================
# Public entry points
# ============================================================================

def parse_msecure_text(file_text: str) -> tuple[list[MSecureRecord], list[str]]:
    """Parse the full text of an mSecure CSV export.

    Returns (parsed records, first physical line of every record that could
    not be parsed).
    """
    # Allow very large notes/fields (the csv module has a small default limit).
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

    record_line_groups = group_lines_into_records(split_into_physical_lines(file_text))

    parsed_records: list[MSecureRecord] = []
    unparsable_record_starts: list[str] = []
    for record_lines in record_line_groups:
        record = parse_record(record_lines)
        if record is None:
            unparsable_record_starts.append(record_lines[0])
        else:
            parsed_records.append(record)
    return parsed_records, unparsable_record_starts


def read_msecure_file(csv_path: Path | str) -> tuple[list[MSecureRecord], list[str]]:
    """Read and parse an mSecure CSV file (same return value as parse_msecure_text).

    Raises UnicodeDecodeError if the file is not valid UTF-8.
    """
    # utf-8-sig transparently removes a BOM if the file has one.
    file_text = Path(csv_path).read_text(encoding="utf-8-sig")
    return parse_msecure_text(file_text)
