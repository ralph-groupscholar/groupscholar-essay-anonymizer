package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestApplyMaskTemplate(t *testing.T) {
	got := applyMaskTemplate("[REDACTED:{label}:{n}:{hash}]", "email", 3, "abc123")
	if got != "[REDACTED:email:3:abc123]" {
		t.Fatalf("unexpected mask template: %s", got)
	}
}

func TestLuhnValidToken(t *testing.T) {
	valid := []string{
		"4111 1111 1111 1111",
		"4012-8888-8888-1881",
	}
	for _, value := range valid {
		if !luhnValidToken(value) {
			t.Fatalf("expected valid luhn for %s", value)
		}
	}
	if luhnValidToken("4111 1111 1111 1112") {
		t.Fatalf("expected invalid luhn for bad value")
	}
}

func TestParseExtensions(t *testing.T) {
	got := parseExtensions("txt, .md ,csv")
	want := map[string]bool{
		".txt": true,
		".md":  true,
		".csv": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected extensions: %#v", got)
	}
}

func TestFilterPatterns(t *testing.T) {
	patterns := []pattern{
		{label: "email"},
		{label: "name:Jordan"},
		{label: "custom:\\b\\d+\\b"},
	}
	filtered := filterPatterns(patterns, []string{"email", "name:*"})
	if len(filtered) != 1 {
		t.Fatalf("unexpected filtered patterns length: %d", len(filtered))
	}
	if filtered[0].label != "custom:\\b\\d+\\b" {
		t.Fatalf("unexpected remaining pattern: %s", filtered[0].label)
	}
}

func TestCollectFilesWithExclusions(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "keep.txt"), "a")
	mustWrite(t, filepath.Join(root, "skip.md"), "b")
	mustMkdir(t, filepath.Join(root, "skipdir"))
	mustWrite(t, filepath.Join(root, "skipdir", "inside.txt"), "c")
	mustMkdir(t, filepath.Join(root, "nested"))
	mustWrite(t, filepath.Join(root, "nested", "ignore.txt"), "d")

	files, err := collectFiles(
		root,
		parseExtensions(".txt,.md"),
		buildExcludeDirs([]string{"skipdir"}),
		buildExcludePaths([]string{filepath.Join("nested", "ignore.txt")}),
	)
	if err != nil {
		t.Fatalf("collectFiles error: %v", err)
	}

	expected := map[string]bool{
		filepath.Join(root, "keep.txt"): true,
		filepath.Join(root, "skip.md"):  true,
	}
	if len(files) != len(expected) {
		t.Fatalf("unexpected file count: %d", len(files))
	}
	for _, file := range files {
		if !expected[file] {
			t.Fatalf("unexpected file: %s", file)
		}
	}
}

func TestRedactFileDryRun(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "essay.txt")
	mustWrite(t, input, "Contact me at test@example.com")
	outputRoot := filepath.Join(root, "out")

	patterns, err := buildPatterns(nil)
	if err != nil {
		t.Fatalf("buildPatterns error: %v", err)
	}

	cfg, err := buildMaskConfig("[REDACTED]", "", false, "", 8)
	if err != nil {
		t.Fatalf("mask config error: %v", err)
	}

	entry, redacted, err := redactFile(input, root, outputRoot, patterns, cfg, true, false)
	if err != nil {
		t.Fatalf("redactFile error: %v", err)
	}

	if entry.Total == 0 {
		t.Fatalf("expected redactions in dry-run")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Fatalf("expected redacted content")
	}

	if _, err := os.Stat(filepath.Join(outputRoot, "essay.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no output file during dry-run")
	}
}

func TestBuildMaskConfigHashTemplate(t *testing.T) {
	_, err := buildMaskConfig("[REDACTED]", "[REDACTED:{label}:{n}]", true, "salt", 8)
	if err == nil {
		t.Fatalf("expected error when hash enabled without {hash}")
	}

	cfg, err := buildMaskConfig("[REDACTED]", "", true, "salt", 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.template == "" || !strings.Contains(cfg.template, "{hash}") {
		t.Fatalf("expected default template with hash, got %q", cfg.template)
	}
}

func TestRedactFileWithHash(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "essay.txt")
	content := "Email me at test@example.com or test@example.com"
	mustWrite(t, input, content)

	patterns, err := buildPatterns(nil)
	if err != nil {
		t.Fatalf("buildPatterns error: %v", err)
	}

	cfg, err := buildMaskConfig("[REDACTED]", "[REDACTED:{label}:{hash}]", true, "salt", 8)
	if err != nil {
		t.Fatalf("mask config error: %v", err)
	}

	outputRoot := filepath.Join(root, "out")
	_, _, err = redactFile(input, root, outputRoot, patterns, cfg, false, false)
	if err != nil {
		t.Fatalf("redactFile error: %v", err)
	}

	redacted, err := os.ReadFile(filepath.Join(outputRoot, "essay.txt"))
	if err != nil {
		t.Fatalf("read redacted error: %v", err)
	}
	result := string(redacted)
	re := regexp.MustCompile(`\[REDACTED:email:([0-9a-f]{8})\]`)
	matches := re.FindAllStringSubmatch(result, -1)
	if len(matches) != 2 {
		t.Fatalf("expected two hashed redactions, got %d (%s)", len(matches), result)
	}
	if matches[0][1] != matches[1][1] {
		t.Fatalf("expected deterministic hashes for same value")
	}
}

func TestRedactContentSkipsInvalidCard(t *testing.T) {
	patterns, err := buildPatterns(nil)
	if err != nil {
		t.Fatalf("buildPatterns error: %v", err)
	}
	cfg, err := buildMaskConfig("[REDACTED]", "", false, "", 8)
	if err != nil {
		t.Fatalf("mask config error: %v", err)
	}
	content := "valid 4111 1111 1111 1111 invalid 4111 1111 1111 1112"
	redacted, counts := redactContent(content, patterns, cfg)
	if strings.Contains(redacted, "4111 1111 1111 1111") {
		t.Fatalf("expected valid card to be redacted")
	}
	if !strings.Contains(redacted, "4111 1111 1111 1112") {
		t.Fatalf("expected invalid card to remain")
	}
	if counts["credit_card"] != 1 {
		t.Fatalf("expected 1 credit_card redaction, got %d", counts["credit_card"])
	}
}

func TestRedactFileSkipClean(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "clean.txt")
	mustWrite(t, input, "Nothing sensitive here.")
	outputRoot := filepath.Join(root, "out")

	patterns, err := buildPatterns(nil)
	if err != nil {
		t.Fatalf("buildPatterns error: %v", err)
	}
	cfg, err := buildMaskConfig("[REDACTED]", "", false, "", 8)
	if err != nil {
		t.Fatalf("mask config error: %v", err)
	}

	entry, _, err := redactFile(input, root, outputRoot, patterns, cfg, false, true)
	if err != nil {
		t.Fatalf("redactFile error: %v", err)
	}
	if !entry.Skipped {
		t.Fatalf("expected clean file to be skipped")
	}
	if _, err := os.Stat(filepath.Join(outputRoot, "clean.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no output file when skip-clean is enabled")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write error: %v", err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir error: %v", err)
	}
}

func TestLoadDBConfigFromDSN(t *testing.T) {
	t.Setenv("GS_PG_DSN", "postgres://user:pass@example.com:5432/dbname?sslmode=require")
	cfg, err := loadDBConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "postgres://user:pass@example.com:5432/dbname?sslmode=require" {
		t.Fatalf("unexpected dsn: %s", cfg.dsn)
	}
}

func TestLoadDBConfigFromParts(t *testing.T) {
	t.Setenv("GS_PG_HOST", "db.example.com")
	t.Setenv("GS_PG_PORT", "5439")
	t.Setenv("GS_PG_USER", "appuser")
	t.Setenv("GS_PG_PASSWORD", "secret")
	t.Setenv("GS_PG_DB", "essay")
	t.Setenv("GS_PG_SSLMODE", "require")

	cfg, err := loadDBConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "postgres://appuser:secret@db.example.com:5439/essay?sslmode=require"
	if cfg.dsn != expected {
		t.Fatalf("unexpected dsn: %s", cfg.dsn)
	}
}
