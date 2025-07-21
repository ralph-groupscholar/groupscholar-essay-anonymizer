# GroupScholar Essay Anonymizer

Local-first CLI that redacts PII in scholarship essays and intake narratives before review. It supports email, phone, SSN, DOB, street address detection, optional name lists, and custom regex patterns.

## Features
- Redacts emails, phone numbers, SSNs, DOBs, and street addresses by default.
- Optional names file to remove known applicant or guardian names.
- Custom regex patterns for program-specific PII.
- Works on a file or an entire directory (with extension filters).
- Generates a JSON report with per-file and per-pattern counts.

## Usage

```bash
go run . -input /path/to/essay.txt
```

```bash
go run . -input /path/to/essays -output /path/to/redacted -extensions .txt,.md -names-file /path/to/names.txt
```

```bash
go run . -input /path/to/essays -custom-regex "\\b\d{6}\\b" -custom-regex "Student ID: \\d+"
```

```bash
go run . -input /path/to/essays -report-csv /path/to/redaction-report.csv
```

```bash
go run . -input /path/to/essays -mask-template "[REDACTED:{label}:{n}]"
```

## Flags
- `-input`: File or directory to redact (required).
- `-output`: Output directory for redacted files (default: `./redacted`).
- `-extensions`: Comma-separated extensions when input is a directory.
- `-mask`: Replacement string for redacted content.
- `-mask-template`: Template for redactions using `{label}` and `{n}` placeholders.
- `-names-file`: File containing names to redact (one per line).
- `-custom-regex`: Repeatable custom regex patterns.
- `-report`: Optional path for the JSON report.
- `-report-csv`: Optional path for a CSV report.

## Output
- Redacted files are written to the output directory, preserving relative paths.
- JSON report includes per-file counts and totals.
- CSV report includes per-file counts, totals, and per-pattern columns.

## Tech
- Go 1.22
