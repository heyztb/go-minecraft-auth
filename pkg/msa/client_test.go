package msa_test

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heyztb/go-minecraft-auth/pkg/msa"
	"golang.org/x/oauth2"
)

func TestMSAClientExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth20_token.srf" {
			t.Logf("Path mismatch. Expected /oauth20_token.srf, got %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		// Set required headers
		w.Header().Set("Content-Type", "application/json")

		// Create mock token response
		response := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  "mock_access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "mock_refresh_token",
		}

		// Send response
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			t.Logf("Error encoding response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()
	client := msa.NewAuthClient(msa.BlockbotAuthConfig{
		AzureApplicationConfig: &msa.AzureApplicationConfig{
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
			RedirectURL:  "http://localhost:8080",
		},
		Endpoints: &msa.Endpoints{
			MSALoginURL:  server.URL + "/oauth20_authorize.srf",
			MSATokenURL:  server.URL + "/oauth20_token.srf",
			XBLAuthURL:   server.URL + "/user/authenticate",
			XSTSAuthURL:  server.URL + "/xsts/authorize",
			MCLoginURL:   server.URL + "/authentication/login_with_xbox",
			MCProfileURL: server.URL + "/minecraft/profile",
		},
	})
	err := client.Exchange("test_code")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if client.MSAToken == nil {
		t.Fatal("Token not set after exchange")
	}
}

func TestXboxLiveAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/authenticate":
			json.NewEncoder(w).Encode(msa.XBLAuthResponse{
				Token: "mock_xbl_token",
				DisplayClaims: struct {
					XUI []struct {
						UHS string `json:"uhs"`
					} `json:"xui"`
				}{
					XUI: []struct {
						UHS string `json:"uhs"`
					}{{UHS: "mock_uhs"}},
				},
			})
		case "/xsts/authorize":
			json.NewEncoder(w).Encode(msa.XSTSAuthResponse{
				Token: "mock_xsts_token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := msa.NewAuthClient(msa.BlockbotAuthConfig{
		AzureApplicationConfig: &msa.AzureApplicationConfig{
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
			RedirectURL:  "http://localhost:8080",
		},
		Endpoints: &msa.Endpoints{
			MSALoginURL:  server.URL + "/oauth20_authorize.srf",
			MSATokenURL:  server.URL + "/oauth20_token.srf",
			XBLAuthURL:   server.URL + "/user/authenticate",
			XSTSAuthURL:  server.URL + "/xsts/authorize",
			MCLoginURL:   server.URL + "/authentication/login_with_xbox",
			MCProfileURL: server.URL + "/minecraft/profile",
		},
	})
	client.MSAToken = &oauth2.Token{
		AccessToken: "mock_access_token",
	}
	_, err := client.AuthenticateWithXBL()
	if err != nil {
		t.Fatalf("XBL authentication failed: %v", err)
	}
	if client.XBLToken != "mock_xbl_token" {
		t.Errorf("Expected XBL token %s, got %s", "mock_xbl_token", client.XBLToken)
	}
	if client.XBLUserHash != "mock_uhs" {
		t.Errorf("Expected UHS %s, got %s", "mock_uhs", client.XBLUserHash)
	}
	_, err = client.AuthenticateWithXSTS()
	if err != nil {
		t.Fatalf("XSTS authentication failed: %v", err)
	}
	if client.XSTSToken != "mock_xsts_token" {
		t.Errorf("Expected XSTS token %s, got %s", "mock_xsts_token", client.XSTSToken)
	}
}

func TestMinecraftAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authentication/login_with_xbox":
			json.NewEncoder(w).Encode(msa.MinecraftAuthResponse{
				AccessToken: "mock_mc_token",
				ExpiresIn:   86400,
			})
		case "/minecraft/profile":
			json.NewEncoder(w).Encode(msa.MinecraftProfile{
				ID:   "mock_profile_id",
				Name: "TestPlayer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := msa.NewAuthClient(msa.BlockbotAuthConfig{
		AzureApplicationConfig: &msa.AzureApplicationConfig{
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
			RedirectURL:  "http://localhost:8080",
		},
		Endpoints: &msa.Endpoints{
			MSALoginURL:  server.URL + "/oauth20_authorize.srf",
			MSATokenURL:  server.URL + "/oauth20_token.srf",
			XBLAuthURL:   server.URL + "/user/authenticate",
			XSTSAuthURL:  server.URL + "/xsts/authorize",
			MCLoginURL:   server.URL + "/authentication/login_with_xbox",
			MCProfileURL: server.URL + "/minecraft/profile",
		},
	})
	client.XBLUserHash = "mock_uhs"
	client.XSTSToken = "mock_xsts_token"
	_, err := client.AuthenticateWithMinecraft()
	if err != nil {
		t.Fatalf("Minecraft authentication failed: %v", err)
	}
	if client.MCToken != "mock_mc_token" {
		t.Errorf("Expected MC token %s, got %s", "mock_mc_token", client.MCToken)
	}
	profile, err := client.GetProfile()
	if err != nil {
		t.Fatalf("Get profile failed: %v", err)
	}
	if profile.ID != "mock_profile_id" || profile.Name != "TestPlayer" {
		t.Errorf("Unexpected profile data: %+v", profile)
	}

} // Error responses from various services
var (
	msaErrorResp = map[string]interface{}{
		"error":             "invalid_grant",
		"error_description": "The provided authorization grant or refresh token is invalid",
	}

	xblErrorResp = map[string]interface{}{
		"error":       "BadRequest",
		"description": "Invalid token format",
	}

	xstsErrorResp = map[string]interface{}{
		"error":       "unauthorized",
		"description": "Token has expired",
	}

	mcErrorResp = map[string]interface{}{
		"error":        "InvalidToken",
		"errorMessage": "The token is invalid",
	}
)

// TestMSAErrorCases tests various error scenarios
func TestMSAErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse map[string]interface{}
		statusCode     int
		expectedError  string
	}{
		{
			name:           "invalid grant error",
			serverResponse: msaErrorResp,
			statusCode:     400,
			expectedError:  "invalid_grant",
		},
		{
			name:           "server error",
			serverResponse: map[string]interface{}{"error": "server_error"},
			statusCode:     500,
			expectedError:  "server_error",
		},
		{
			name:           "network error",
			serverResponse: nil,
			statusCode:     0, // Server will be stopped for this test
			expectedError:  "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			if tt.statusCode > 0 {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.statusCode)
					json.NewEncoder(w).Encode(tt.serverResponse)
				}))
				defer server.Close()
			} else {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				server.Close() // Immediately close to simulate network error
			}

			client := msa.NewAuthClient(msa.BlockbotAuthConfig{
				AzureApplicationConfig: &msa.AzureApplicationConfig{
					ClientID:     "mock_client_id",
					ClientSecret: "mock_client_secret",
					RedirectURL:  "http://localhost:8080",
				},
				Endpoints: &msa.Endpoints{
					MSALoginURL:  server.URL + "/oauth20_authorize.srf",
					MSATokenURL:  server.URL + "/oauth20_token.srf",
					XBLAuthURL:   server.URL + "/user/authenticate",
					XSTSAuthURL:  server.URL + "/xsts/authorize",
					MCLoginURL:   server.URL + "/authentication/login_with_xbox",
					MCProfileURL: server.URL + "/minecraft/profile",
				},
			})

			err := client.Exchange("test_code")
			if err == nil {
				t.Error("Expected error but got none")
				return
			}

			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("Expected error containing %q, got %q", tt.expectedError, err.Error())
			}
		})
	}
}

// TestTokenRefresh tests the token refresh functionality
func TestTokenRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "refresh_token=mock_refresh_token") {
			t.Errorf("Expected refresh token in body, got %s", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		response := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}{
			AccessToken:  "new_access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new_refresh_token",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := msa.NewAuthClient(msa.BlockbotAuthConfig{
		AzureApplicationConfig: &msa.AzureApplicationConfig{
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
			RedirectURL:  "http://localhost:8080",
		},
		Endpoints: &msa.Endpoints{
			MSALoginURL:  server.URL + "/oauth20_authorize.srf",
			MSATokenURL:  server.URL + "/oauth20_token.srf",
			XBLAuthURL:   server.URL + "/user/authenticate",
			XSTSAuthURL:  server.URL + "/xsts/authorize",
			MCLoginURL:   server.URL + "/authentication/login_with_xbox",
			MCProfileURL: server.URL + "/minecraft/profile",
		},
	})

	// Set an expired token
	client.MSAToken = &oauth2.Token{
		AccessToken:  "old_access_token",
		TokenType:    "Bearer",
		RefreshToken: "mock_refresh_token",
		Expiry:       time.Now().Add(-time.Hour),
	}

	err := client.RefreshToken()
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	// Verify the token was updated
	if client.MSAToken.AccessToken != "new_access_token" {
		t.Errorf("Expected new access token, got %s", client.MSAToken.AccessToken)
	}

	if client.MSAToken.RefreshToken != "new_refresh_token" {
		t.Errorf("Expected new refresh token, got %s", client.MSAToken.RefreshToken)
	}

	// Verify the expiry was set correctly
	expectedExpiry := time.Now().Add(3600 * time.Second)
	if math.Abs(client.MSAToken.Expiry.Sub(expectedExpiry).Seconds()) > 5 {
		t.Errorf("Token expiry not set correctly. Expected around %v, got %v",
			expectedExpiry, client.MSAToken.Expiry)
	}
}

// TestFullAuthenticationChain tests the complete authentication flow
func TestFullAuthenticationChain(t *testing.T) {
	// Create test server that handles all endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth20_token.srf":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "mock_msa_token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock_refresh_token",
			})

		case "/user/authenticate":
			json.NewEncoder(w).Encode(msa.XBLAuthResponse{
				Token: "mock_xbl_token",
				DisplayClaims: struct {
					XUI []struct {
						UHS string `json:"uhs"`
					} `json:"xui"`
				}{
					XUI: []struct {
						UHS string `json:"uhs"`
					}{{UHS: "mock_uhs"}},
				},
			})

		case "/xsts/authorize":
			json.NewEncoder(w).Encode(msa.XSTSAuthResponse{
				Token: "mock_xsts_token",
				DisplayClaims: struct {
					XUI []struct {
						UHS string `json:"uhs"`
					} `json:"xui"`
				}{
					XUI: []struct {
						UHS string `json:"uhs"`
					}{{UHS: "mock_uhs"}},
				},
			})

		case "/authentication/login_with_xbox":
			json.NewEncoder(w).Encode(msa.MinecraftAuthResponse{
				AccessToken: "mock_mc_token",
				ExpiresIn:   86400,
			})

		case "/minecraft/profile":
			json.NewEncoder(w).Encode(msa.MinecraftProfile{
				ID:   "mock_profile_id",
				Name: "TestPlayer",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create client and run through full authentication chain
	client := msa.NewAuthClient(msa.BlockbotAuthConfig{
		AzureApplicationConfig: &msa.AzureApplicationConfig{
			ClientID:     "mock_client_id",
			ClientSecret: "mock_client_secret",
			RedirectURL:  "http://localhost:8080",
		},
		Endpoints: &msa.Endpoints{
			MSALoginURL:  server.URL + "/oauth20_authorize.srf",
			MSATokenURL:  server.URL + "/oauth20_token.srf",
			XBLAuthURL:   server.URL + "/user/authenticate",
			XSTSAuthURL:  server.URL + "/xsts/authorize",
			MCLoginURL:   server.URL + "/authentication/login_with_xbox",
			MCProfileURL: server.URL + "/minecraft/profile",
		},
	})

	err := client.Exchange("test_code")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	// XBL Authentication
	_, err = client.AuthenticateWithXBL()
	if err != nil {
		t.Fatalf("XBL authentication failed: %v", err)
	}

	// XSTS Authentication
	_, err = client.AuthenticateWithXSTS()
	if err != nil {
		t.Fatalf("XSTS authentication failed: %v", err)
	}

	// Minecraft Authentication
	_, err = client.AuthenticateWithMinecraft()
	if err != nil {
		t.Fatalf("Minecraft authentication failed: %v", err)
	}

	// Get Profile
	profile, err := client.GetProfile()
	if err != nil {
		t.Fatalf("Get profile failed: %v", err)
	}

	// Verify final state
	expectedChecks := []struct {
		name     string
		got      string
		expected string
	}{
		{"MSA Token", client.MSAToken.AccessToken, "mock_msa_token"},
		{"XBL Token", client.XBLToken, "mock_xbl_token"},
		{"XSTS Token", client.XSTSToken, "mock_xsts_token"},
		{"Minecraft Token", client.MCToken, "mock_mc_token"},
		{"Profile ID", profile.ID, "mock_profile_id"},
		{"Profile Name", profile.Name, "TestPlayer"},
	}

	for _, check := range expectedChecks {
		if check.got != check.expected {
			t.Errorf("%s: expected %s, got %s", check.name, check.expected, check.got)
		}
	}
}
