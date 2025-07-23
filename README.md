# GroupScholar Essay Anonymizer

Local-first CLI that redacts PII in scholarship essays and intake narratives before review. It supports email, phone, SSN, DOB, street address detection, plus URL, IP address, and credit card detection (with Luhn validation), optional name lists, and custom regex patterns.

## Features
- Redacts emails, phone numbers, SSNs, DOBs, street addresses, URLs, IP addresses, and credit card numbers by default.
- Optional names file to remove known applicant or guardian names.
- Custom regex patterns for program-specific PII.
- Works on a file or an entire directory (with extension filters).
- Exclude directories or specific relative paths during directory scans.
- Dry-run mode to preview redactions without writing files.
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

```bash
go run . -input /path/to/essays -exclude-dir node_modules -exclude-path drafts/essay.txt
```

```bash
go run . -input /path/to/essays -dry-run
```

## Flags
- `-input`: File or directory to redact (required).
- `-output`: Output directory for redacted files (default: `./redacted`).
- `-extensions`: Comma-separated extensions when input is a directory.
- `-mask`: Replacement string for redacted content.
- `-mask-template`: Template for redactions using `{label}` and `{n}` placeholders.
- `-names-file`: File containing names to redact (one per line).
- `-custom-regex`: Repeatable custom regex patterns.
- `-exclude-dir`: Repeatable directory name to skip when walking a directory.
- `-exclude-path`: Repeatable relative path to skip when walking a directory.
- `-dry-run`: Preview redactions without writing files.
- `-report`: Optional path for the JSON report.
- `-report-csv`: Optional path for a CSV report.

## Output
- Redacted files are written to the output directory, preserving relative paths.
- Dry-run mode still writes reports but does not write redacted files.
- JSON report includes per-file counts and totals.
- CSV report includes per-file counts, totals, and per-pattern columns.

## Tech
- Go 1.22
