"""Convert mSecure 6/7 CSV exports into (unencrypted) Bitwarden JSON files."""

# Defined first: pyproject.toml reads it, and the CLI imports it.
__version__ = "1.0.0"

from .bitwarden import convert_to_bitwarden  # noqa: E402
from .msecure import (  # noqa: E402
    MSecureField,
    MSecureRecord,
    parse_msecure_text,
    read_msecure_file,
)

__all__ = [
    "__version__",
    "MSecureField",
    "MSecureRecord",
    "convert_to_bitwarden",
    "parse_msecure_text",
    "read_msecure_file",
]
