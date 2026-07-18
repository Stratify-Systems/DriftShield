package baseline

import (
	"encoding/json"
	"os"
)

// LoadBaseline loads a JSON baseline from the specified path.
func LoadBaseline[T any](path string) (*T, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bl T
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

// SaveBaseline saves a baseline as formatted JSON to the specified path.
func SaveBaseline[T any](path string, bl *T) error {
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
