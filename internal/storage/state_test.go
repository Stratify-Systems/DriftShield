package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadLocally(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baselines", "test_baseline.json")
	data := []byte(`{"created_at":"2025-01-01T00:00:00Z"}`)

	// Save
	if err := SaveBaseline(context.Background(), path, data); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("baseline file was not created")
	}

	// Load
	loaded, err := LoadBaseline(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if string(loaded) != string(data) {
		t.Errorf("loaded data = %q; want %q", loaded, data)
	}
}

func TestLoadLocallyNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	_, err := LoadBaseline(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if err != ErrBaselineNotFound {
		t.Errorf("expected ErrBaselineNotFound, got: %v", err)
	}
}

func TestSaveCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "deep.json")

	if err := SaveBaseline(context.Background(), path, []byte("test")); err != nil {
		t.Fatalf("SaveBaseline failed to create nested dirs: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file not readable: %v", err)
	}
	if string(data) != "test" {
		t.Errorf("data = %q; want %q", data, "test")
	}
}

func TestOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	// Write v1
	if err := SaveBaseline(context.Background(), path, []byte("v1")); err != nil {
		t.Fatal(err)
	}

	// Overwrite with v2
	if err := SaveBaseline(context.Background(), path, []byte("v2")); err != nil {
		t.Fatal(err)
	}

	data, _ := LoadBaseline(context.Background(), path)
	if string(data) != "v2" {
		t.Errorf("expected v2 after overwrite, got %q", data)
	}
}
