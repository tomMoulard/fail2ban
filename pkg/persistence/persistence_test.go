package persistence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "fail2ban-test-*")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to cleanup test directory: %v", err)
		}
	})

	testFile := filepath.Join(tmpDir, "blocked-ips.json")
	store := NewFileStore(testFile)

	// Test data
	now := time.Now()
	testBlocks := []BlockedIP{
		{
			IP:       "192.0.2.1",
			BannedAt: now,
			BanUntil: now.Add(time.Hour),
		},
		{
			IP:       "192.0.2.2",
			BannedAt: now,
			BanUntil: now.Add(2 * time.Hour),
		},
	}

	// Test Save
	t.Run("save blocks", func(t *testing.T) {
		t.Parallel()

		err := store.Save(context.Background(), testBlocks)
		if err != nil {
			t.Errorf("Save() error = %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			t.Error("Save() did not create file")
		}
	})

	// Test Load
	t.Run("load blocks", func(t *testing.T) {
		t.Parallel()

		blocks, err := store.Load(context.Background())
		if err != nil {
			t.Errorf("Load() error = %v", err)
		}

		if len(blocks) != len(testBlocks) {
			t.Errorf("Load() got %v blocks, want %v", len(blocks), len(testBlocks))
		}

		// Verify loaded data
		for i, block := range blocks {
			if block.IP != testBlocks[i].IP {
				t.Errorf("Load() block[%d].IP = %v, want %v", i, block.IP, testBlocks[i].IP)
			}

			if !block.BannedAt.Equal(testBlocks[i].BannedAt) {
				t.Errorf("Load() block[%d].BannedAt = %v, want %v", i, block.BannedAt, testBlocks[i].BannedAt)
			}

			if !block.BanUntil.Equal(testBlocks[i].BanUntil) {
				t.Errorf("Load() block[%d].BanUntil = %v, want %v", i, block.BanUntil, testBlocks[i].BanUntil)
			}
		}
	})

	// Test Load with non-existent file
	t.Run("load non-existent file", func(t *testing.T) {
		t.Parallel()

		nonExistentStore := NewFileStore(filepath.Join(tmpDir, "non-existent.json"))

		blocks, err := nonExistentStore.Load(context.Background())
		if err != nil {
			t.Errorf("Load() error = %v", err)
		}

		if blocks != nil {
			t.Errorf("Load() got %v, want nil", blocks)
		}
	})

	// Test Load with invalid JSON
	t.Run("load invalid json", func(t *testing.T) {
		t.Parallel()

		invalidFile := filepath.Join(tmpDir, "invalid.json")

		const filePermission = 0o600

		err := os.WriteFile(invalidFile, []byte("invalid json"), filePermission)
		if err != nil {
			t.Fatal(err)
		}

		invalidStore := NewFileStore(invalidFile)

		_, err = invalidStore.Load(context.Background())
		if err == nil {
			t.Error("Load() expected error with invalid JSON")
		}
	})
}
