# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-11

### Added
- Initial release.
- Converts mSecure 6/7 CSV exports to unencrypted Bitwarden JSON.
- Correct handling of multi-line notes and field values (mSecure writes them
  unquoted, with a literal backslash-n at the start of each continuation line).
- Mapping of Login, Credit Card and Secure Note records; other record types are
  converted to logins (when they hold credentials) or to secure notes.
- `--folder-by-type` switch to create one Bitwarden folder per mSecure record type
  (no folders are created by default).
- Fields without a value are discarded.
- `--version` option and `python -m msecure_to_bitwarden` entry point.
