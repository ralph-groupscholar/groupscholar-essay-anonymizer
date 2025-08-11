# Ralph Progress Log

## 2026-02-07
- Initialized groupscholar-essay-anonymizer Go CLI project.
- Implemented PII redaction for email, phone, SSN, DOB, street address, plus names file and custom regex support.
- Added JSON reporting and README with usage.

## 2026-02-08
- Added optional CSV reporting with per-file and per-pattern counts.
- Updated documentation with CSV report usage and output details.

## 2026-02-08
- Added URL, IP address, and credit card detection (Luhn-validated).
- Added credit card validation to mask templates and standard masking.
- Updated README to reflect the expanded default redaction set.
- Added mask template support for labeled redactions with sequential IDs.

## 2026-02-08
- Added dry-run support plus directory and path exclusions for safer batch scans.
- Added Go tests covering redaction helpers, exclusions, and dry-run behavior.
- Updated README with new flags and examples.

## 2026-02-08
- Added optional PostgreSQL run logging with schema auto-creation and env-based DSN config.
- Added seed data to production database for run_log and documented DB logging usage.
- Added tests for DB configuration assembly and updated dependencies.

## 2026-02-08
- Added skip-clean mode to avoid writing files when no redactions are found, with report + CSV tracking.
- Updated tests and CLI summaries for skip-clean runs.
- Updated README with skip-clean usage and flag details.

## 2026-02-08
- Added disable-pattern flag with exact and prefix matching to skip specific redaction patterns.
- Added tests for pattern filtering and updated README with usage/flag details.

## 2026-02-08
- Added hashed redaction support with configurable salt and hash length, plus template {hash} placeholder.
- Updated redaction pipeline and tests to cover deterministic hashed tokens.
- Refreshed README with new hash flags and usage example.
