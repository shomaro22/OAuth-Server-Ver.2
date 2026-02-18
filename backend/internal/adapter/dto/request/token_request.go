package request

// AuthCodeTokenRequest は認可コードによるトークン交換のリクエスト DTO。
type AuthCodeTokenRequest struct {
	GrantType    string `form:"grant_type"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	CodeVerifier string `form:"code_verifier"`
}

// RefreshTokenRequest はリフレッシュトークンによるトークン交換のリクエスト DTO。
type RefreshTokenRequest struct {
	GrantType    string `form:"grant_type"`
	RefreshToken string `form:"refresh_token"`
	ClientID     string `form:"client_id"`
}
