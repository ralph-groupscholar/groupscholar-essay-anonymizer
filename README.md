# GroupScholar Essay Anonymizer

Local-first CLI that redacts PII in scholarship essays and intake narratives before review. It supports email, phone, SSN, DOB, street address detection, plus URL, IP address, and credit card detection (with Luhn validation), optional name lists, and custom regex patterns.

## Features
- Redacts emails, phone numbers, SSNs, DOBs, street addresses, URLs, IP addresses, and credit card numbers by default.
- Optional names file to remove known applicant or guardian names.
- Custom regex patterns for program-specific PII.
- Works on a file or an entire directory (with extension filters).
- Exclude directories or specific relative paths during directory scans.
- Dry-run mode to preview redactions without writing files.
- Optional stdout output for single-file redaction.
- Generates a JSON report with per-file and per-pattern counts.
- Optional hash-aware masks for deterministic anonymized tokens.
- Optional PostgreSQL logging for run summaries.

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
go run . -input /path/to/essays -disable-pattern name:* -disable-pattern phone
```

```bash
go run . -input /path/to/essays -report-csv /path/to/redaction-report.csv
```

```bash
go run . -input /path/to/essays -mask-template "[REDACTED:{label}:{n}]"
```

```bash
go run . -input /path/to/essays -hash -hash-salt "gs-essay" -mask-template "[REDACTED:{label}:{hash}]"
```

```bash
go run . -input /path/to/essays -exclude-dir node_modules -exclude-path drafts/essay.txt
```

```bash
go run . -input /path/to/essays -dry-run
```

```bash
go run . -input /path/to/essay.txt -stdout
```

```bash
GS_PG_HOST=... GS_PG_PORT=... GS_PG_USER=... GS_PG_PASSWORD=... GS_PG_DB=... \
  go run . -input /path/to/essays -db-log
```

## Flags
- `-input`: File or directory to redact (required).
- `-output`: Output directory for redacted files (default: `./redacted`).
- `-extensions`: Comma-separated extensions when input is a directory.
- `-mask`: Replacement string for redacted content.
- `-mask-template`: Template for redactions using `{label}`, `{n}`, and `{hash}` placeholders.
- `-hash`: Enable hashed redaction tokens (requires `{hash}` in template or uses default template).
- `-hash-salt`: Optional salt for hashed tokens.
- `-hash-length`: Length of the hash fragment included in masked output.
- `-names-file`: File containing names to redact (one per line).
- `-custom-regex`: Repeatable custom regex patterns.
- `-disable-pattern`: Repeatable pattern label to disable (`*` suffix for prefix match).
- `-exclude-dir`: Repeatable directory name to skip when walking a directory.
- `-exclude-path`: Repeatable relative path to skip when walking a directory.
- `-dry-run`: Preview redactions without writing files.
- `-stdout`: Print redacted output to stdout (single-file only).
- `-report`: Optional path for the JSON report.
- `-report-csv`: Optional path for a CSV report.
- `-db-log`: Write a run summary to PostgreSQL.

## Output
- Redacted files are written to the output directory, preserving relative paths.
- Dry-run mode still writes reports but does not write redacted files.
- Stdout mode forces dry-run and prints redacted content for piping.
- JSON report includes per-file counts and totals.
- CSV report includes per-file counts, totals, and per-pattern columns.

## Database Logging
Set `-db-log` to store a run summary in `groupscholar_essay_anonymizer.run_log`.

Supported environment variables:
- `GS_PG_DSN`: Full DSN (overrides the fields below).
- `GS_PG_HOST`, `GS_PG_PORT`, `GS_PG_USER`, `GS_PG_PASSWORD`, `GS_PG_DB`, `GS_PG_SSLMODE`.
`GS_PG_SSLMODE` defaults to `disable` if omitted.

## Tech
- Go 1.24
