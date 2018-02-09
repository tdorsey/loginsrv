package model

// DiscoveryDocument gets the OAuth Endpoint urls dynamically
// See https://developers.google.com/identity/protocols/OpenIDConnect#discovery

type Scope struct {
	Name string `json:"scopes_supported"`
}

type DiscoveryDocument struct {
	Issuer                string `json:"issuer,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	ScopesSupported       []Scope
}
