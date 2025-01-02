// Package persistence provides a simple file-based persistence mechanism for storing and retrieving blocked IPs.
package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DirectoryPermission defines the permission for created directories.
	DirectoryPermission = 0o750
	// FilePermission defines the permission for the persistence file.
	FilePermission = 0o600
)

// BlockedIP represents a blocked IP with its ban duration.
type BlockedIP struct {
	IP       string    `json:"ip"`
	BannedAt time.Time `json:"bannedAt"`
	BanUntil time.Time `json:"banUntil"`
	RuleID   string    `json:"ruleId,omitempty"` // Cloudflare rule ID
}

// Store defines the interface for persistence operations.
type Store interface {
	Load(ctx context.Context) ([]BlockedIP, error)
	Save(ctx context.Context, blocks []BlockedIP) error
	AddIP(ctx context.Context, block BlockedIP) error
	RemoveIP(ctx context.Context, ip string) error
	RemoveByRuleID(ctx context.Context, ruleID string) error
	UpdateRuleID(ctx context.Context, ip string, ruleID string) error
}

// FileStore implements Store interface using file storage.
type FileStore struct {
	path string
	mu   sync.RWMutex
}

func NewFileStore(path string) *FileStore {
	fmt.Printf("[Persistence] Creating new file store with path: %s\n", path)

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

	fmt.Printf("[Persistence] Attempting to save %d IPs to %s\n", len(ips), f.path)

	// Check if directory exists and is writable
	dir := filepath.Dir(f.path)

	info, err := os.Stat(dir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to check directory %s: %w", dir, err)
	}

	if os.IsNotExist(err) {
		fmt.Printf("[Persistence] Directory %s does not exist, creating...\n", dir)

		if err := os.MkdirAll(dir, DirectoryPermission); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("path %s exists but is not a directory", dir)
	}

	// Try to create a test file to verify write permissions
	testFile := filepath.Join(dir, ".test")
	if err := os.WriteFile(testFile, []byte("test"), FilePermission); err != nil {
		return fmt.Errorf("directory %s is not writable: %w", dir, err)
	}

	if err := os.Remove(testFile); err != nil {
		fmt.Printf("[Persistence] Warning: Failed to remove test file: %v\n", err)
	}

	data, err := json.MarshalIndent(ips, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blocked IPs: %w", err)
	}

	if err := os.WriteFile(f.path, data, FilePermission); err != nil {
		fmt.Printf("[Persistence] Error writing file: %v\n", err)

		return fmt.Errorf("failed to write blocked IPs file: %w", err)
	}

	fmt.Printf("[Persistence] Successfully saved blocked IPs to %s\n", f.path)

	return nil
}

// RemoveIP removes an IP from the persisted block list.
func (f *FileStore) RemoveIP(ctx context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	blocks, err := f.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load blocks: %w", err)
	}

	var newBlocks []BlockedIP

	for _, block := range blocks {
		if block.IP != ip {
			newBlocks = append(newBlocks, block)
		}
	}

	return f.Save(ctx, newBlocks)
}

// UpdateRuleID updates the rule ID for a blocked IP.
func (f *FileStore) UpdateRuleID(ctx context.Context, ip string, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	blocks, err := f.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load blocks: %w", err)
	}

	for i := range blocks {
		if blocks[i].IP == ip {
			blocks[i].RuleID = ruleID

			break
		}
	}

	return f.Save(ctx, blocks)
}

func (f *FileStore) AddIP(ctx context.Context, block BlockedIP) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	blocks, err := f.Load(ctx)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load blocks: %w", err)
	}

	// Check if IP already exists
	for i, b := range blocks {
		if b.IP == block.IP {
			blocks[i] = block

			return f.Save(ctx, blocks)
		}
	}

	blocks = append(blocks, block)

	return f.Save(ctx, blocks)
}

func (f *FileStore) RemoveByRuleID(ctx context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	blocks, err := f.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load blocks: %w", err)
	}

	var newBlocks []BlockedIP

	for _, block := range blocks {
		if block.RuleID != ruleID {
			newBlocks = append(newBlocks, block)
		}
	}

	return f.Save(ctx, newBlocks)
}
