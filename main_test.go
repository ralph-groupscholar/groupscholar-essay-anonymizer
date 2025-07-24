package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApplyMaskTemplate(t *testing.T) {
	got := applyMaskTemplate("[REDACTED:{label}:{n}]", "email", 3)
	if got != "[REDACTED:email:3]" {
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

	entry, err := redactFile(input, root, outputRoot, patterns, "[REDACTED]", "", true)
	if err != nil {
		t.Fatalf("redactFile error: %v", err)
	}

	if entry.Total == 0 {
		t.Fatalf("expected redactions in dry-run")
	}

	if _, err := os.Stat(filepath.Join(outputRoot, "essay.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no output file during dry-run")
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
