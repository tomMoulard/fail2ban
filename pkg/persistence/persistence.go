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
	DirectoryPermission = 0o777
	// FilePermission defines the permission for the persistence file.
	FilePermission = 0o644
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

	// Create file with empty array if it doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("[Persistence] Creating initial file at %s\n", path)
		if err := os.WriteFile(path, []byte("[]"), FilePermission); err != nil {
			fmt.Printf("[Persistence] Warning: Failed to create initial file: %v\n", err)
		}
	}

	return &FileStore{path: path}
}

func (f *FileStore) Load(ctx context.Context) ([]BlockedIP, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	fmt.Printf("[Persistence] Loading blocks from %s\n", f.path)

	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		fmt.Printf("[Persistence] File does not exist, returning empty list\n")
		return make([]BlockedIP, 0), nil
	}

	if err != nil {
		fmt.Printf("[Persistence] Error reading file: %v\n", err)
		return nil, fmt.Errorf("failed to read blocked IPs file: %w", err)
	}

	fmt.Printf("[Persistence] Read data: %s\n", string(data))

	var ips []BlockedIP
	if err := json.Unmarshal(data, &ips); err != nil {
		fmt.Printf("[Persistence] Error unmarshaling data: %v\n", err)
		return nil, fmt.Errorf("failed to parse blocked IPs file: %w", err)
	}

	if ips == nil {
		ips = make([]BlockedIP, 0)
	}

	fmt.Printf("[Persistence] Successfully loaded %d blocks\n", len(ips))
	return ips, nil
}

func (f *FileStore) Save(ctx context.Context, ips []BlockedIP) error {
	if ips == nil {
		ips = make([]BlockedIP, 0)
	}

	fmt.Printf("[Persistence] Save operation started with %d IPs\n", len(ips))

	// Ensure absolute path
	absPath, err := filepath.Abs(f.path)
	if err != nil {
		fmt.Printf("[Persistence] Error getting absolute path: %v\n", err)
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fmt.Printf("[Persistence] Attempting to save %d IPs to %s (absolute path: %s)\n",
		len(ips), f.path, absPath)

	dir := filepath.Dir(absPath)
	fmt.Printf("[Persistence] Directory to create/use: %s\n", dir)

	// Verify file permissions before writing
	if info, err := os.Stat(absPath); err == nil {
		fmt.Printf("[Persistence] Existing file permissions: %v\n", info.Mode())
	}

	// Marshal with indentation for readability
	data, err := json.MarshalIndent(ips, "", "  ")
	if err != nil {
		fmt.Printf("[Persistence] Failed to marshal data: %v\n", err)
		return fmt.Errorf("failed to marshal blocked IPs: %w", err)
	}

	fmt.Printf("[Persistence] Successfully marshaled data: %s\n", string(data))

	// Create a temporary file in the same directory
	tmpFile := absPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, FilePermission); err != nil {
		fmt.Printf("[Persistence] Failed to write temporary file %s: %v\n", tmpFile, err)
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Sync the temporary file to disk
	if f, err := os.OpenFile(tmpFile, os.O_RDWR, FilePermission); err == nil {
		f.Sync()
		f.Close()
	}

	// Atomically rename temporary file to target file
	if err := os.Rename(tmpFile, absPath); err != nil {
		fmt.Printf("[Persistence] Failed to rename temporary file to %s: %v\n", absPath, err)
		os.Remove(tmpFile) // Clean up temp file
		return fmt.Errorf("failed to save blocked IPs file: %w", err)
	}

	fmt.Printf("[Persistence] Successfully saved %d blocked IPs to %s\n", len(ips), absPath)
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
	fmt.Printf("[Persistence] Adding IP %s to persistence (banned until: %s)\n",
		block.IP, block.BanUntil.Format(time.RFC3339))

	// Read existing blocks without holding the write lock
	blocks, err := f.Load(ctx)
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("[Persistence] Error loading existing blocks: %v\n", err)
		return fmt.Errorf("failed to load blocks: %w", err)
	}

	if blocks == nil {
		blocks = make([]BlockedIP, 0)
	}

	fmt.Printf("[Persistence] Current working directory: %s\n", getCurrentDirectory())
	fmt.Printf("[Persistence] File store path: %s\n", f.path)
	fmt.Printf("[Persistence] Directory permissions: %s\n", getDirectoryPermissions(filepath.Dir(f.path)))
	fmt.Printf("[Persistence] Current blocks: %+v\n", blocks)

	// Remove any existing block for this IP and add the new one
	var newBlocks []BlockedIP
	for _, b := range blocks {
		if b.IP != block.IP {
			newBlocks = append(newBlocks, b)
		}
	}

	// Add the new block
	newBlocks = append(newBlocks, block)
	fmt.Printf("[Persistence] Added new block for IP %s, total blocks: %d\n", block.IP, len(newBlocks))
	fmt.Printf("[Persistence] Blocks to save: %+v\n", newBlocks)

	// Now acquire the lock only for saving
	f.mu.Lock()
	defer f.mu.Unlock()

	// Save the updated blocks
	if err := f.Save(ctx, newBlocks); err != nil {
		fmt.Printf("[Persistence] Failed to save blocks: %v\n", err)
		return err
	}

	fmt.Printf("[Persistence] Successfully saved block for IP %s\n", block.IP)
	return nil
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

func getCurrentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("error getting current directory: %v", err)
	}
	return dir
}

func getDirectoryPermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("directory does not exist: %v", err)
		}
		return fmt.Sprintf("error getting directory info: %v", err)
	}
	return fmt.Sprintf("mode: %v", info.Mode())
}
