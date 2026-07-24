package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/storage"
)

func TestSaveAndLoadLocally(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baselines", "test_baseline.json")
	data := []byte(`{"created_at":"2025-01-01T00:00:00Z"}`)

	if err := storage.SaveBaseline(context.Background(), path, data); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("baseline file was not created")
	}

	loaded, err := storage.LoadBaseline(context.Background(), path)
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

	_, err := storage.LoadBaseline(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if err != storage.ErrBaselineNotFound {
		t.Errorf("expected ErrBaselineNotFound, got: %v", err)
	}
}
