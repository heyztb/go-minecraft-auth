package msa_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/heyztb/go-minecraft-auth/pkg/msa"
)

// TestCallbackServer tests the callback server functionality
func TestCallbackServer(t *testing.T) {
	codeChannel := make(chan string, 1)
	server := msa.NewCallbackServer(codeChannel)

	// Start server in goroutine
	go func() {
		if err := server.Start(); err != http.ErrServerClosed {
			t.Errorf("Unexpected server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test successful code reception
	resp, err := http.Get("http://localhost:8080/?code=test_auth_code")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	select {
	case code := <-codeChannel:
		if code != "test_auth_code" {
			t.Errorf("Expected code test_auth_code, got %s", code)
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for code")
	}

	// Test missing code parameter
	resp, err = http.Get("http://localhost:8080/")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	// Cleanup
	server.Stop()
}
