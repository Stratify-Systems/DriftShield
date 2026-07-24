package baseline

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/SuryaTK2007/DriftShield/internal/storage"
)

// LoadBaseline loads a JSON baseline from the specified path via storage.
// Returns (nil, nil) if the baseline does not exist yet.
func LoadBaseline[T any](path string) (*T, error) {
	data, err := storage.LoadBaseline(context.Background(), path)
	if err != nil {
		if errors.Is(err, storage.ErrBaselineNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var bl T
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

// SaveBaseline saves a baseline as formatted JSON to the specified path via storage.
func SaveBaseline[T any](path string, bl *T) error {
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return err
	}
	return storage.SaveBaseline(context.Background(), path, data)
}
