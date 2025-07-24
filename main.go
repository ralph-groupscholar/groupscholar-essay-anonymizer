package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

import _ "github.com/jackc/pgx/v5/stdlib"

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("custom regex cannot be empty")
	}
	*s = append(*s, value)
	return nil
}

type pattern struct {
	label string
	re    *regexp.Regexp
}

type fileReport struct {
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Redactions map[string]int `json:"redactions"`
	Total      int            `json:"total"`
}

type report struct {
	GeneratedAt string         `json:"generated_at"`
	InputPath   string         `json:"input_path"`
	OutputPath  string         `json:"output_path"`
	Files       int            `json:"files"`
	Total       int            `json:"total_redactions"`
	ByPattern   map[string]int `json:"by_pattern"`
	Details     []fileReport   `json:"details"`
}

func main() {
	inputPath := flag.String("input", "", "File or directory to redact")
	outputPath := flag.String("output", "", "Output directory for redacted files (default: ./redacted)")
	extensions := flag.String("extensions", ".txt,.md,.csv", "Comma-separated list of file extensions to include when input is a directory")
	mask := flag.String("mask", "[REDACTED]", "Text to replace redactions with")
	maskTemplate := flag.String("mask-template", "", "Template for redactions using {label} and {n} placeholders")
	namesFile := flag.String("names-file", "", "Optional file with names to redact (one per line)")
	reportPath := flag.String("report", "", "Optional path for JSON report (default: <output>/redaction-report.json)")
	reportCSVPath := flag.String("report-csv", "", "Optional path for CSV report")
	dbLog := flag.Bool("db-log", false, "Log run summary to PostgreSQL (requires GS_PG_* env vars)")
	dryRun := flag.Bool("dry-run", false, "Preview redactions without writing files")
	var customRegex stringList
	flag.Var(&customRegex, "custom-regex", "Custom regex to redact (repeatable)")
	var excludeDirs stringList
	var excludePaths stringList
	flag.Var(&excludeDirs, "exclude-dir", "Directory name to skip (repeatable)")
	flag.Var(&excludePaths, "exclude-path", "Relative path to skip (repeatable)")
	flag.Parse()

	if strings.TrimSpace(*inputPath) == "" {
		exitWith("-input is required")
	}

	absInput, err := filepath.Abs(*inputPath)
	if err != nil {
		exitWith("failed to resolve input path: " + err.Error())
	}

	info, err := os.Stat(absInput)
	if err != nil {
		exitWith("failed to access input path: " + err.Error())
	}

	outDir := strings.TrimSpace(*outputPath)
	if !*dryRun {
		if outDir == "" {
			outDir = filepath.Join(".", "redacted")
		}
		outDir, err = filepath.Abs(outDir)
		if err != nil {
			exitWith("failed to resolve output path: " + err.Error())
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			exitWith("failed to create output directory: " + err.Error())
		}
	} else if outDir != "" {
		outDir, err = filepath.Abs(outDir)
		if err != nil {
			exitWith("failed to resolve output path: " + err.Error())
		}
	}

	patterns, err := buildPatterns(customRegex)
	if err != nil {
		exitWith(err.Error())
	}

	if *namesFile != "" {
		names, err := loadNames(*namesFile)
		if err != nil {
			exitWith("failed to read names file: " + err.Error())
		}
		patterns = append(patterns, buildNamePatterns(names)...)
	}

	if len(patterns) == 0 {
		exitWith("no patterns configured")
	}

	allowedExt := parseExtensions(*extensions)
	var files []string
	if info.IsDir() {
		files, err = collectFiles(absInput, allowedExt, buildExcludeDirs(excludeDirs), buildExcludePaths(excludePaths))
		if err != nil {
			exitWith("failed to collect files: " + err.Error())
		}
	} else {
		files = []string{absInput}
	}

	if len(files) == 0 {
		exitWith("no files to process")
	}

	outputLabel := outDir
	if *dryRun {
		if outputLabel == "" {
			outputLabel = "(dry-run)"
		}
	}
	rep := report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		InputPath:   absInput,
		OutputPath:  outputLabel,
		ByPattern:   map[string]int{},
	}

	for _, path := range files {
		entry, err := redactFile(path, absInput, outDir, patterns, *mask, *maskTemplate, *dryRun)
		if err != nil {
			exitWith(fmt.Sprintf("failed to redact %s: %v", path, err))
		}
		rep.Files++
		rep.Total += entry.Total
		for label, count := range entry.Redactions {
			rep.ByPattern[label] += count
		}
		rep.Details = append(rep.Details, entry)
	}

	sort.Slice(rep.Details, func(i, j int) bool {
		return rep.Details[i].Source < rep.Details[j].Source
	})

	if *reportPath == "" {
		if *dryRun {
			*reportPath = filepath.Join(".", "redaction-report.json")
		} else {
			*reportPath = filepath.Join(outDir, "redaction-report.json")
		}
	}
	if err := writeReport(*reportPath, rep); err != nil {
		exitWith("failed to write report: " + err.Error())
	}

	if *reportCSVPath != "" {
		if err := writeCSVReport(*reportCSVPath, rep); err != nil {
			exitWith("failed to write CSV report: " + err.Error())
		}
	}

	if *dbLog {
		if err := logRun(rep, *reportPath, *reportCSVPath, *dryRun); err != nil {
			exitWith("failed to log to database: " + err.Error())
		}
	}

	printSummary(rep, *reportPath)
}

func exitWith(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func buildPatterns(custom []string) ([]pattern, error) {
	patterns := []pattern{
		{label: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)},
		{label: "phone", re: regexp.MustCompile(`(?i)(?:\+?1[\s.-]?)?(?:\(\s*\d{3}\s*\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}`)},
		{label: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{label: "dob", re: regexp.MustCompile(`\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b`)},
		{label: "street_address", re: regexp.MustCompile(`\b\d+\s+[A-Za-z0-9.\-\s]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b`)},
		{label: "url", re: regexp.MustCompile(`\bhttps?://[^\s]+`)},
		{label: "ip_address", re: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
		{label: "credit_card", re: regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
	}

	for _, raw := range custom {
		re, err := regexp.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid custom regex %q: %w", raw, err)
		}
		patterns = append(patterns, pattern{label: "custom:" + raw, re: re})
	}

	return patterns, nil
}

func loadNames(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var names []string
	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func buildNamePatterns(names []string) []pattern {
	var patterns []pattern
	for _, name := range names {
		escaped := regexp.QuoteMeta(name)
		patterns = append(patterns, pattern{
			label: "name:" + name,
			re:    regexp.MustCompile(`(?i)\b` + escaped + `\b`),
		})
	}
	return patterns
}

func parseExtensions(raw string) map[string]bool {
	result := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		ext := strings.ToLower(strings.TrimSpace(part))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		result[ext] = true
	}
	return result
}

func buildExcludeDirs(values []string) map[string]bool {
	result := map[string]bool{}
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		result[filepath.Base(trimmed)] = true
	}
	return result
}

func buildExcludePaths(values []string) map[string]bool {
	result := map[string]bool{}
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		cleaned := filepath.Clean(trimmed)
		cleaned = strings.TrimPrefix(cleaned, string(os.PathSeparator))
		if cleaned == "." {
			continue
		}
		result[cleaned] = true
	}
	return result
}

func collectFiles(root string, allowedExt map[string]bool, excludeDirs map[string]bool, excludePaths map[string]bool) ([]string, error) {
	var files []string
	root = filepath.Clean(root)
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			if rel, err := filepath.Rel(root, path); err == nil {
				rel = filepath.Clean(rel)
				if excludePaths[rel] {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
		}
		if d.IsDir() {
			if excludeDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if len(allowedExt) > 0 && !allowedExt[ext] {
			return nil
		}
		files = append(files, path)
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		return nil, err
	}
	return files, nil
}

func redactFile(path, inputRoot, outputRoot string, patterns []pattern, mask string, maskTemplate string, dryRun bool) (fileReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fileReport{}, err
	}

	content := string(data)
	redactions := map[string]int{}
	maskTemplate = strings.TrimSpace(maskTemplate)
	for _, pat := range patterns {
		if maskTemplate != "" {
			counter := 0
			content = pat.re.ReplaceAllStringFunc(content, func(match string) string {
				if pat.label == "credit_card" && !luhnValidToken(match) {
					return match
				}
				counter++
				redactions[pat.label]++
				return applyMaskTemplate(maskTemplate, pat.label, counter)
			})
			continue
		}
		if pat.label == "credit_card" {
			content = pat.re.ReplaceAllStringFunc(content, func(match string) string {
				if !luhnValidToken(match) {
					return match
				}
				redactions[pat.label]++
				return mask
			})
			continue
		}
		matches := pat.re.FindAllStringIndex(content, -1)
		if len(matches) == 0 {
			continue
		}
		redactions[pat.label] += len(matches)
		content = pat.re.ReplaceAllString(content, mask)
	}

	rel := path
	if info, err := os.Stat(inputRoot); err == nil && info.IsDir() {
		if relPath, err := filepath.Rel(inputRoot, path); err == nil {
			rel = relPath
		}
	}

	target := ""
	if outputRoot != "" {
		target = filepath.Join(outputRoot, rel)
	}
	if !dryRun {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fileReport{}, err
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return fileReport{}, err
		}
	}

	total := 0
	for _, count := range redactions {
		total += count
	}

	return fileReport{
		Source:     path,
		Target:     target,
		Redactions: redactions,
		Total:      total,
	}, nil
}

func applyMaskTemplate(template, label string, index int) string {
	out := strings.ReplaceAll(template, "{label}", label)
	return strings.ReplaceAll(out, "{n}", fmt.Sprintf("%d", index))
}

func luhnValidToken(raw string) bool {
	digits := strings.ReplaceAll(raw, " ", "")
	digits = strings.ReplaceAll(digits, "-", "")
	return luhnValid(digits)
}

func luhnValid(number string) bool {
	if len(number) < 13 || len(number) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		ch := number[i]
		if ch < '0' || ch > '9' {
			return false
		}
		digit := int(ch - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func writeReport(path string, rep report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCSVReport(path string, rep report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	labels := make([]string, 0, len(rep.ByPattern))
	for label := range rep.ByPattern {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	header := append([]string{"source", "target", "total_redactions"}, labels...)
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, entry := range rep.Details {
		row := []string{entry.Source, entry.Target, fmt.Sprintf("%d", entry.Total)}
		for _, label := range labels {
			row = append(row, fmt.Sprintf("%d", entry.Redactions[label]))
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func printSummary(rep report, reportPath string) {
	fmt.Printf("Redacted %d files. Total redactions: %d\n", rep.Files, rep.Total)
	labels := make([]string, 0, len(rep.ByPattern))
	for label := range rep.ByPattern {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Printf("  %s: %d\n", label, rep.ByPattern[label])
	}
	fmt.Printf("Report: %s\n", reportPath)
}

type dbConfig struct {
	dsn string
}

func loadDBConfig() (dbConfig, error) {
	if dsn := strings.TrimSpace(os.Getenv("GS_PG_DSN")); dsn != "" {
		return dbConfig{dsn: dsn}, nil
	}

	host := strings.TrimSpace(os.Getenv("GS_PG_HOST"))
	user := strings.TrimSpace(os.Getenv("GS_PG_USER"))
	password := os.Getenv("GS_PG_PASSWORD")
	port := strings.TrimSpace(os.Getenv("GS_PG_PORT"))
	database := strings.TrimSpace(os.Getenv("GS_PG_DB"))
	sslmode := strings.TrimSpace(os.Getenv("GS_PG_SSLMODE"))

	if host == "" || user == "" || password == "" {
		return dbConfig{}, errors.New("missing GS_PG_HOST, GS_PG_USER, or GS_PG_PASSWORD")
	}
	if port == "" {
		port = "5432"
	}
	if database == "" {
		database = "postgres"
	}
	if sslmode == "" {
		sslmode = "disable"
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%s", host, port),
		Path:   database,
	}
	query := url.Values{}
	query.Set("sslmode", sslmode)
	u.RawQuery = query.Encode()
	return dbConfig{dsn: u.String()}, nil
}

func logRun(rep report, reportPath, reportCSVPath string, dryRun bool) error {
	cfg, err := loadDBConfig()
	if err != nil {
		return err
	}

	db, err := sql.Open("pgx", cfg.dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `
		CREATE SCHEMA IF NOT EXISTS groupscholar_essay_anonymizer;
		CREATE TABLE IF NOT EXISTS groupscholar_essay_anonymizer.run_log (
			id BIGSERIAL PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			generated_at TIMESTAMPTZ,
			input_path TEXT NOT NULL,
			output_path TEXT NOT NULL,
			dry_run BOOLEAN NOT NULL,
			file_count INTEGER NOT NULL,
			total_redactions INTEGER NOT NULL,
			by_pattern JSONB NOT NULL,
			report_path TEXT NOT NULL,
			report_csv_path TEXT
		);
	`); err != nil {
		return err
	}

	byPattern, err := json.Marshal(rep.ByPattern)
	if err != nil {
		return err
	}

	generatedAt, err := time.Parse(time.RFC3339, rep.GeneratedAt)
	if err != nil {
		generatedAt = time.Now()
	}

	csvPath := sql.NullString{Valid: false}
	if strings.TrimSpace(reportCSVPath) != "" {
		csvPath = sql.NullString{String: reportCSVPath, Valid: true}
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO groupscholar_essay_anonymizer.run_log (
			generated_at,
			input_path,
			output_path,
			dry_run,
			file_count,
			total_redactions,
			by_pattern,
			report_path,
			report_csv_path
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);
	`, generatedAt, rep.InputPath, rep.OutputPath, dryRun, rep.Files, rep.Total, byPattern, reportPath, csvPath)
	return err
}
