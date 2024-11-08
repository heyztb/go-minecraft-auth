// MSA request/response types
package msa

// Xbox Live types
type XBLProperties struct {
	AuthMethod string `json:"AuthMethod"`
	SiteName   string `json:"SiteName"`
	RpsTicket  string `json:"RpsTicket"`
}

type XBLAuthRequest struct {
	Properties   XBLProperties `json:"Properties"`
	RelyingParty string        `json:"RelyingParty"`
	TokenType    string        `json:"TokenType"`
}

type XBLAuthResponse struct {
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

// XSTS types
type XSTSProperties struct {
	SandboxId  string   `json:"SandboxId"`
	UserTokens []string `json:"UserTokens"`
}

type XSTSAuthRequest struct {
	Properties   XSTSProperties `json:"Properties"`
	RelyingParty string         `json:"RelyingParty"`
	TokenType    string         `json:"TokenType"`
}

type XSTSAuthResponse struct {
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

// Minecraft authentication types
type MinecraftAuthRequest struct {
	IdentityToken string `json:"identityToken"`
}

type MinecraftAuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Minecraft profile types
type MinecraftProfile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Skins      []Skin `json:"skins"`
	Capes      []Cape `json:"capes"`
	ProfileURL string `json:"profileUrl"`
}

type Skin struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	URL     string `json:"url"`
	Variant string `json:"variant"`
}

type Cape struct {
	ID    string `json:"id"`
	State string `json:"state"`
	URL   string `json:"url"`
	Alias string `json:"alias"`
}
