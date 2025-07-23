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
