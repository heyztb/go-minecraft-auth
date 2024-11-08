package msa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	MSALoginURL  = "https://login.live.com/oauth20_authorize.srf"
	MSATokenURL  = "https://login.live.com/oauth20_token.srf"
	XBLAuthURL   = "https://user.auth.xboxlive.com/user/authenticate"
	XSTSAuthURL  = "https://xsts.auth.xboxlive.com/xsts/authorize"
	MCLoginURL   = "https://api.minecraftservices.com/authentication/login_with_xbox"
	MCProfileURL = "https://api.minecraftservices.com/minecraft/profile"
)

type AzureApplicationConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type Endpoints struct {
	MSALoginURL  string
	MSATokenURL  string
	XBLAuthURL   string
	XSTSAuthURL  string
	MCLoginURL   string
	MCProfileURL string
}

type BlockbotAuthConfig struct {
	*AzureApplicationConfig
	*Endpoints
}

type MinecraftAuthClient struct {
	*Endpoints
	config      *oauth2.Config
	verifier    string
	MSAToken    *oauth2.Token
	XBLToken    string
	XBLUserHash string
	XSTSToken   string
	MCToken     string
	CodeChannel chan string
}

func NewAuthClient(config BlockbotAuthConfig) *MinecraftAuthClient {
	if config.Endpoints == nil {
		config.Endpoints = &Endpoints{
			MSALoginURL:  MSALoginURL,
			MSATokenURL:  MSATokenURL,
			XBLAuthURL:   XBLAuthURL,
			XSTSAuthURL:  XSTSAuthURL,
			MCLoginURL:   MCLoginURL,
			MCProfileURL: MCProfileURL,
		}
	}

	return &MinecraftAuthClient{
		Endpoints: config.Endpoints,
		config: &oauth2.Config{
			ClientID:     config.AzureApplicationConfig.ClientID,
			ClientSecret: config.AzureApplicationConfig.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.Endpoints.MSALoginURL,
				TokenURL: config.Endpoints.MSATokenURL,
			},
			RedirectURL: config.AzureApplicationConfig.RedirectURL,
			Scopes:      []string{"XboxLive.signin", "offline_access"},
		},
		CodeChannel: make(chan string, 1),
	}
}

func (ac *MinecraftAuthClient) AuthCodeURL() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(buf)
	pkceVerifier := oauth2.GenerateVerifier()
	ac.verifier = pkceVerifier
	return ac.config.AuthCodeURL(state, oauth2.S256ChallengeOption(pkceVerifier)), nil
}

func (ac *MinecraftAuthClient) CallbackHandler() error {
	server := NewCallbackServer(ac.CodeChannel)
	defer server.Stop()
	go func() {
		server.Start()
	}()
	timer := time.NewTimer(1 * time.Minute)
	select {
	case code := <-ac.CodeChannel:
		err := ac.Exchange(code)
		if err != nil {
			return err
		}
		timer.Stop()
	case <-timer.C:
		return errors.New("timeout waiting for code, please restart login process")
	}
	return nil
}

func (ac *MinecraftAuthClient) Exchange(code string) error {
	token, err := ac.config.Exchange(context.Background(), code, oauth2.VerifierOption(ac.verifier))
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	ac.MSAToken = token
	return nil
}

func (ac *MinecraftAuthClient) RefreshToken() error {
	if ac.MSAToken == nil {
		return errors.New("no token to refresh")
	}
	if time.Now().Before(ac.MSAToken.Expiry) {
		return errors.New("token has not expired")
	}
	client := ac.config.Client(context.Background(), ac.MSAToken)
	data := url.Values{}
	data.Set("client_id", ac.config.ClientID)
	data.Set("client_secret", ac.config.ClientSecret)
	data.Set("refresh_token", ac.MSAToken.RefreshToken)
	data.Set("grant_type", "refresh_token")
	data.Set("redirect_uri", ac.config.RedirectURL)
	request, err := http.NewRequest("POST", ac.Endpoints.MSATokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create refresh token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to do refresh token request: %w", err)
	}
	defer response.Body.Close()
	token := &oauth2.Token{}
	if err := json.NewDecoder(response.Body).Decode(token); err != nil {
		return fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	ac.MSAToken = token
	return nil
}

func (ac *MinecraftAuthClient) AuthenticateWithXBL() (*XBLAuthResponse, error) {
	request := XBLAuthRequest{
		Properties: XBLProperties{
			AuthMethod: "RPS",
			SiteName:   "user.auth.xboxlive.com",
			RpsTicket:  fmt.Sprintf("d=%s", ac.MSAToken.AccessToken),
		},
		RelyingParty: "http://auth.xboxlive.com",
		TokenType:    "JWT",
	}
	respBody, err := ac.postJSON(ac.Endpoints.XBLAuthURL, request)
	if err != nil {
		return nil, err
	}
	var xblResp XBLAuthResponse
	if err := json.Unmarshal(respBody, &xblResp); err != nil {
		return nil, err
	}
	ac.XBLToken = xblResp.Token
	ac.XBLUserHash = xblResp.DisplayClaims.XUI[0].UHS
	return &xblResp, nil
}

func (ac *MinecraftAuthClient) AuthenticateWithXSTS() (*XSTSAuthResponse, error) {
	request := XSTSAuthRequest{
		Properties: XSTSProperties{
			SandboxId:  "RETAIL",
			UserTokens: []string{ac.XBLToken},
		},
		RelyingParty: "rp://api.minecraftservices.com/",
		TokenType:    "JWT",
	}
	respBody, err := ac.postJSON(ac.Endpoints.XSTSAuthURL, request)
	if err != nil {
		return nil, err
	}
	var xstsResp XSTSAuthResponse
	if err := json.Unmarshal(respBody, &xstsResp); err != nil {
		return nil, err
	}
	ac.XSTSToken = xstsResp.Token
	return &xstsResp, nil
}

func (ac *MinecraftAuthClient) AuthenticateWithMinecraft() (*MinecraftAuthResponse, error) {
	request := MinecraftAuthRequest{
		IdentityToken: fmt.Sprintf("XBL3.0 x=%s;%s", ac.XBLUserHash, ac.XSTSToken),
	}
	respBody, err := ac.postJSON(ac.Endpoints.MCLoginURL, request)
	if err != nil {
		return nil, err
	}
	var mcResp MinecraftAuthResponse
	if err := json.Unmarshal(respBody, &mcResp); err != nil {
		return nil, err
	}
	ac.MCToken = mcResp.AccessToken
	return &mcResp, nil
}

func (ac *MinecraftAuthClient) GetProfile() (*MinecraftProfile, error) {
	request, err := http.NewRequest("GET", ac.Endpoints.MCProfileURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.MCToken))
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to do profile fetch request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("profile fetch failed: (%d status) -  %s", resp.StatusCode, string(body))
	}
	var profile MinecraftProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (ac *MinecraftAuthClient) postJSON(url string, payload interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(string(body))
	}
	return body, nil
}
