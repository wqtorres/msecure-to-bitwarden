# msecure-to-bitwarden

[![CI](https://github.com/wqtorres/msecure-to-bitwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/wqtorres/msecure-to-bitwarden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Convert an **mSecure 6/7 CSV export** into an **unencrypted Bitwarden JSON file** that you can import into
Bitwarden (or any tool that reads Bitwarden JSON, such as KeePassXC).

- Handles mSecure's quirky multi-line notes correctly (see [the file format](#the-msecure-csv-format)).
- Maps logins, credit cards and secure notes to the matching Bitwarden item types.
- Pure Python standard library: no dependencies, works offline, your data never leaves your machine.

> **Not affiliated with mSecure or Bitwarden.** "mSecure" and "Bitwarden" are trademarks of their respective owners.

## ⚠️ Security notice

The generated JSON file contains **all of your passwords in plaintext**, and so does the mSecure CSV export.

- Run the tool on a machine you trust, import the result, then **delete both files securely**.
- The output file is created readable by its owner only (mode `0600`) on systems that support it.
- Never commit exports to Git (this repository's `.gitignore` blocks `*.csv` and `*.bitwarden.json`),
  and never attach them to issues. If you report a bug, use a small **sanitized** sample with fake data.

## Installation

Requires Python 3.9 or newer.

```bash
# Recommended: isolated install with pipx
pipx install git+https://github.com/wqtorres/msecure-to-bitwarden.git

# or with pip
pip install git+https://github.com/wqtorres/msecure-to-bitwarden.git

# or from a clone
git clone https://github.com/wqtorres/msecure-to-bitwarden.git
cd msecure-to-bitwarden
pip install .
```

## Usage

1. Export your data from mSecure as **CSV** (mSecure 6 or 7).
2. Convert it:

   ```bash
   msecure-to-bitwarden export.csv
   ```

   This writes `export.bitwarden.json` next to the input file. `python -m msecure_to_bitwarden ...` works too.
3. Import the JSON into Bitwarden: web vault → **Tools → Import data** → file format **Bitwarden (json)**
   (or use the CLI: `bw import bitwarden export.bitwarden.json`).
4. Delete `export.csv` and `export.bitwarden.json` securely.

### Command line arguments

```
msecure-to-bitwarden INPUT [-o OUTPUT] [--folder-by-type]
msecure-to-bitwarden -h | --version
```

| Argument | Description |
|---|---|
| `INPUT` | **Required.** The mSecure 6/7 CSV export (UTF-8, a BOM is accepted). The first line is a banner and is ignored. The file is only read, never modified. |
| `-o OUTPUT`, `--output OUTPUT` | Bitwarden JSON file to create. Default: the input path with its extension replaced by `.bitwarden.json` (`export.csv` → `export.bitwarden.json`). An existing file is overwritten without asking; using the input file itself as output is refused. |
| `--folder-by-type` | Create one Bitwarden folder per mSecure record type (Login, Credit Card, Passport, ...) and put each item in the folder of its type. **Without this switch no folders are created.** |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Show the built-in help and exit. |

Examples:

```bash
msecure-to-bitwarden export.csv                                   # -> export.bitwarden.json, no folders
msecure-to-bitwarden export.csv -o vault.json                     # choose the output file
msecure-to-bitwarden export.csv -o vault.json --folder-by-type    # one folder per record type
msecure-to-bitwarden "My Export.csv" -o "My Vault.json"           # quote paths with spaces
```

**Exit codes:** `0` all records converted · `1` file written but some records could not be parsed (a `WARNING`
line is printed for each) · `2` invalid command line, unreadable/non-UTF-8 input, or output equal to input
(nothing is written).

## What gets converted

### Record types

| mSecure record type | Bitwarden item |
|---|---|
| Login | **Login** (username, password, URLs, TOTP) |
| Credit Card | **Card** (number, brand, expiry, holder, security code) |
| Secure Note | **Secure note** |
| Any other type that has a URL, username, password or one-time-password field (Email Account, Router Settings, ...) | **Login**, plus a custom field `mSecure type` with the original type |
| Any other type (Bank Account, Passport, Identity, Vehicle Info, ...) | **Secure note** with every field as a custom field, plus `mSecure type` |

### Fields

| mSecure field type | Result |
|---|---|
| URL | Login URI (all of them are kept) |
| Username / Password / One Time Password | Login username / password / TOTP (the first of each; extra ones become custom fields) |
| Credit Card Number, Month/Year | Card number (brand detected from the number) and expiry |
| Password, Sensitive Number, Credit Card Number, One Time Password (when not used above) | **Hidden** custom field |
| Everything else (text, phone, email, date, ...) | Text custom field |

### Other rules

- **Fields without a value are discarded.**
- **Tags** have no Bitwarden equivalent: all tags of a record are saved in a text custom field named `Tags`.
- **Folders:** none by default; `--folder-by-type` creates one per record type. Tags are never used as folders.
- **Notes** keep their line breaks.
- The output only contains the object that matches each item's type (`login`, `card` or `secureNote`). Unused
  objects are not written, not even as `null`: KeePassXC creates empty `identity_name`/`identity_address`
  attributes for every item that merely has an `identity` key.

## The mSecure CSV format

Documented here because it is not publicly specified and needs care when parsing.

- UTF-8 text. The first row is a banner such as `mSecure6 CSV export file`; the rest has no header row.
- Columns:
  1. `Title|ID` (title and numeric ID joined by a pipe; the whole column is quoted if the title contains commas)
  2. Record type (`Login`, `Credit Card`, `Secure Note`, `Bank Account`, `Birthdays`, `Calling Card`, `Clothes Size`,
     `Combination`, `Drivers License`, `Email Account`, `Frequent Flyer`, `Identity`, `Insurance Info`, `Membership`,
     `Outdoor License`, `Passport`, `Prescription`, `Registration Code`, `Reward Program`, `Router Settings`,
     `Social Security`, `Software License`, `Type`, `Vehicle Info`, `Voice Mail`)
  3. Tags, comma separated (quoted when there are several)
  4. Notes
  5. and onwards: record-specific fields, each as `Field name|Field type|Field value`
- Field types: `0` text · `1` text (no auto-correct) · `2` URL · `3` alphanumeric · `4` phone · `5` email · `6` number ·
  `7` username · `8` password · `9` sensitive number · `10` date · `11` month/year · `12` credit card number ·
  `13` one-time password.
- **Line breaks are not quoted.** A line break inside a value is written as a real line break followed by a literal
  backslash-n at the start of the next physical line. A record can therefore span several lines. This tool treats
  a line starting with a literal `\n` as a continuation of the previous record, and a line shaped like
  `Title|ID,...` as the start of a new one.

## Status and limitations

- The converter is covered by automated tests that use **synthetic** data only. mSecure exports can vary, so if
  something is converted incorrectly, please open an issue with a *sanitized* sample.
- Expiration dates are understood in the formats `MM/YY`, `MM/YYYY` and `YYYY-MM[-DD]`. Anything else is kept
  as a plain custom field.
- Other date fields are copied as text, exactly as exported.
- mSecure attachments and images are not part of the CSV export, so they cannot be migrated.
- Bitwarden "identity" items are not generated; mSecure's Identity records become secure notes.
- Only unencrypted Bitwarden JSON is produced.

## Development

```bash
git clone https://github.com/wqtorres/msecure-to-bitwarden.git
cd msecure-to-bitwarden
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Project layout:

```
src/msecure_to_bitwarden/
    msecure.py      reads and parses the mSecure CSV (record detection, line breaks, fields)
    bitwarden.py    converts parsed records into the Bitwarden JSON structure
    cli.py          command line interface
tests/              pytest suite; tests/data/sample_export.csv is FAKE data
```

The library can also be used from Python:

```python
import json
from msecure_to_bitwarden import read_msecure_file, convert_to_bitwarden

records, unparsable = read_msecure_file("export.csv")
data = convert_to_bitwarden(records, folder_by_type=False)
print(json.dumps(data, indent=2))
```

## Contributing

Issues and pull requests are welcome. Please add or update tests for any behaviour change, and **never include
real passwords or personal data** in code, tests or issues.

## License

[MIT](LICENSE)
