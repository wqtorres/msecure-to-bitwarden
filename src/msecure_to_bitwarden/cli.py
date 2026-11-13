"""Command line interface of msecure-to-bitwarden.

SYNOPSIS
    msecure-to-bitwarden INPUT [-o OUTPUT] [--folder-by-type]
    msecure-to-bitwarden -h | --version
    python -m msecure_to_bitwarden ...        (equivalent)

ARGUMENTS
    INPUT                  (required, positional)
        Path to the mSecure 6 or 7 CSV export. The file must be UTF-8
        (a BOM is accepted). The first line is treated as a banner and
        discarded. The file is only read, never modified.

    -o OUTPUT, --output OUTPUT      (optional)
        Path of the Bitwarden JSON file to create.
        Default: the input path with its extension replaced by
        ".bitwarden.json", in the same folder as the input
        (export.csv -> export.bitwarden.json).
        An existing file at that path is overwritten without asking.
        The script refuses to use the input file itself as the output.
        The output is created with owner-only permissions (0600) on systems
        that support them.

    --folder-by-type                (optional switch, no value)
        When given, one Bitwarden folder is created per mSecure record type
        (Login, Credit Card, Passport, ...) and every item is placed in the
        folder of its type.
        When omitted (default), NO folders are created at all.
        mSecure tags are never used for folders; all tags of a record are
        saved in a custom field called "Tags" (records without tags get no
        such field).

    --version
        Print the program version and exit.

    -h, --help
        Show the built-in help (arguments plus examples) and exit.

EXIT CODES
    0   every record was converted
    1   the file was written, but at least one record could not be parsed
        (a WARNING line for each one is printed to stderr)
    2   invalid command line (missing/unknown argument, input file not found
        or not valid UTF-8, output path equal to the input path, output file
        not writable); nothing is written
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .bitwarden import convert_to_bitwarden
from .msecure import read_msecure_file

PROGRAM_NAME = "msecure-to-bitwarden"
DEFAULT_OUTPUT_SUFFIX = ".bitwarden.json"


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all options and their documentation."""
    # RawDescriptionHelpFormatter keeps the line breaks of the description and
    # epilog below exactly as written (the default formatter would re-wrap them).
    argument_parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        # No prefix matching: "--folder-by" must not silently act as an
        # abbreviation of "--folder-by-type".
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Convert an mSecure 6/7 CSV export into an unencrypted Bitwarden "
            "JSON file.\n"
            "\n"
            "The generated file contains ALL passwords in plaintext. Import it "
            "into Bitwarden,\n"
            "then delete it (and the original CSV) securely."
        ),
        epilog=(
            "examples:\n"
            "  %(prog)s export.csv\n"
            "      Writes export.bitwarden.json next to export.csv.\n"
            "\n"
            "  %(prog)s export.csv -o bitwarden.json\n"
            "      Writes the result to bitwarden.json.\n"
            "\n"
            "  %(prog)s export.csv -o bitwarden.json --folder-by-type\n"
            "      Creates one Bitwarden folder per mSecure record type.\n"
            "\n"
            "  %(prog)s \"My Export.csv\" -o \"My Vault.json\"\n"
            "      Quote paths that contain spaces.\n"
            "\n"
            "exit codes:\n"
            "  0  all records converted\n"
            "  1  file written, but some records could not be parsed (see warnings)\n"
            "  2  invalid arguments, unreadable input, or output equals input\n"
            "\n"
            "import into Bitwarden:\n"
            "  Web vault: Tools > Import data > format \"Bitwarden (json)\" > pick the\n"
            "  generated file. The CLI equivalent is: bw import bitwarden <file>"
        ),
    )

    # Positional argument: the only mandatory one.
    argument_parser.add_argument(
        "input",
        type=Path,
        metavar="INPUT",
        help=(
            "mSecure 6/7 CSV export to convert (UTF-8). The first line is "
            "treated as a banner and ignored. The file is only read, never "
            "modified."
        ),
    )

    # Optional output path; when omitted it is derived from the input path.
    argument_parser.add_argument(
        "-o", "--output",
        type=Path,
        metavar="OUTPUT",
        help=(
            "Bitwarden JSON file to create. Default: the input path with its "
            "extension replaced by .bitwarden.json (export.csv -> "
            "export.bitwarden.json). An existing file is overwritten without "
            "asking; the input file itself is refused."
        ),
    )

    # On/off switch: when omitted (False) no folders are created at all.
    argument_parser.add_argument(
        "--folder-by-type",
        action="store_true",
        help=(
            "Create one Bitwarden folder per mSecure record type (Login, "
            "Credit Card, Secure Note, ...) and place each item in the folder "
            "of its type. Without this switch no folders are created. "
            "mSecure tags are not used for folders; they are saved in a "
            "custom field named 'Tags'."
        ),
    )

    argument_parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return argument_parser


def write_private_file(output_path: Path, text: str) -> None:
    """Write text to a file that only its owner can read.

    The file is created with mode 0600 from the start (no window in which
    it is readable by others). The final chmod also fixes the permissions of a
    pre-existing file. On systems without Unix permissions it is skipped.
    """
    file_descriptor = os.open(
        output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
        output_file.write(text)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    """Run the converter. Returns the process exit code (see module docstring)."""
    argument_parser = build_argument_parser()
    arguments = argument_parser.parse_args(argv)

    # Work out where the result will be written.
    output_path = arguments.output or arguments.input.with_suffix(DEFAULT_OUTPUT_SUFFIX)

    # Validate the paths early so we fail with a clear message (exit code 2)
    # instead of a traceback, and never destroy the user's original export.
    if not arguments.input.is_file():
        argument_parser.error(f"input file not found: {arguments.input}")
    if output_path.resolve() == arguments.input.resolve():
        argument_parser.error("the output file must be different from the input file")

    # Read the mSecure export.
    try:
        records, unparsable_record_starts = read_msecure_file(arguments.input)
    except UnicodeDecodeError:
        argument_parser.error(f"input file is not valid UTF-8: {arguments.input}")
    for record_start in unparsable_record_starts:
        print(f"WARNING: could not parse record starting with: {record_start[:60]!r}",
              file=sys.stderr)

    # Convert and write the Bitwarden JSON.
    bitwarden_data = convert_to_bitwarden(records, arguments.folder_by_type)
    try:
        write_private_file(
            output_path, json.dumps(bitwarden_data, indent=2, ensure_ascii=False)
        )
    except OSError as error:
        argument_parser.error(f"cannot write output file {output_path}: {error}")

    # Print a short summary to stderr.
    records_per_type = Counter(record.record_type for record in records)
    print(f"Read {len(records)} records ({len(unparsable_record_starts)} failed) "
          f"-> {output_path}", file=sys.stderr)
    for record_type, count in records_per_type.most_common():
        print(f"  {record_type}: {count}", file=sys.stderr)
    print("REMINDER: the output file is plaintext. Delete it after importing.",
          file=sys.stderr)

    # Non-zero exit code if any record could not be parsed.
    return 0 if not unparsable_record_starts else 1
