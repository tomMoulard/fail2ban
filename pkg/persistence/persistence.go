// Package persistence provides a simple file-based persistence mechanism for storing and retrieving blocked IPs.
package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// BlockedIP represents a blocked IP with its ban duration.
type BlockedIP struct {
	IP       string    `json:"ip"`
	BannedAt time.Time `json:"bannedAt"`
	BanUntil time.Time `json:"banUntil"`
}

// Store interface for persisting blocked IPs.
type Store interface {
	Load(ctx context.Context) ([]BlockedIP, error)
	Save(ctx context.Context, ips []BlockedIP) error
}

// FileStore implements Store using a JSON file.
type FileStore struct {
	path string
	mu   sync.RWMutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (f *FileStore) Load(ctx context.Context) ([]BlockedIP, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read blocked IPs file: %w", err)
	}

	var ips []BlockedIP
	if err := json.Unmarshal(data, &ips); err != nil {
		return nil, fmt.Errorf("failed to parse blocked IPs file: %w", err)
	}

	return ips, nil
}

func (f *FileStore) Save(ctx context.Context, ips []BlockedIP) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := json.MarshalIndent(ips, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blocked IPs: %w", err)
	}

	const filePermission = 0o600
	if err := os.WriteFile(f.path, data, filePermission); err != nil {
		return fmt.Errorf("failed to write blocked IPs file: %w", err)
	}

	return nil
}
