package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomMoulard/fail2ban/pkg/persistence"
)

func TestBlockIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ip          string
		banDuration time.Duration
		serverResp  interface{}
		statusCode  int
		wantErr     bool
	}{
		{
			name:        "successful block",
			ip:          "192.0.2.1",
			banDuration: time.Hour,
			serverResp: CloudflareResponse{
				Success: true,
			},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:        "api error",
			ip:          "192.0.2.2",
			banDuration: time.Hour,
			serverResp: CloudflareResponse{
				Success: false,
				Errors: []CloudflareError{
					{Code: 1000, Message: "Invalid request"},
				},
			},
			statusCode: http.StatusOK,
			wantErr:    true,
		},
		{
			name:        "server error",
			ip:          "192.0.2.3",
			banDuration: time.Hour,
			statusCode:  http.StatusInternalServerError,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)

				if tt.serverResp != nil {
					err := json.NewEncoder(w).Encode(tt.serverResp)
					if err != nil {
						t.Fatal(err)
					}
				}
			}))
			defer server.Close()

			client := &Client{
				apiToken: "test-token",
				zoneID:   "test-zone",
				baseURL:  server.URL,
			}

			err := client.BlockIP(context.Background(), tt.ip, tt.banDuration)
			if (err != nil) != tt.wantErr {
				t.Errorf("BlockIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadExistingBlocks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serverResp interface{}
		statusCode int
		wantBlocks []persistence.BlockedIP
		wantErr    bool
	}{
		{
			name: "successful load",
			serverResp: struct {
				Result []struct {
					ID            string    `json:"id"`
					CreatedOn     time.Time `json:"createdOn"`
					Configuration struct {
						Value string `json:"value"`
					} `json:"configuration"`
					Notes string `json:"notes"`
				} `json:"result"`
			}{
				Result: []struct {
					ID            string    `json:"id"`
					CreatedOn     time.Time `json:"createdOn"`
					Configuration struct {
						Value string `json:"value"`
					} `json:"configuration"`
					Notes string `json:"notes"`
				}{
					{
						ID:        "1",
						CreatedOn: time.Now(),
						Configuration: struct {
							Value string `json:"value"`
						}{
							Value: "192.0.2.1",
						},
						Notes: "Blocked by Traefik fail2ban plugin (duration: 1h0m0s)",
					},
				},
			},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)

				if tt.serverResp != nil {
					if err := json.NewEncoder(w).Encode(tt.serverResp); err != nil {
						fmt.Printf("failed to encode response: %v\n", err)
					}
				}
			}))
			defer server.Close()

			client := &Client{
				apiToken: "test-token",
				zoneID:   "test-zone",
				baseURL:  server.URL,
			}

			blocks, err := client.LoadExistingBlocks(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadExistingBlocks() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && len(blocks) != len(tt.wantBlocks) {
				t.Errorf("LoadExistingBlocks() got %v blocks, want %v", len(blocks), len(tt.wantBlocks))
			}
		})
	}
}
