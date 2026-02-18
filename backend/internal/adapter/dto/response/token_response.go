package response

// TokenResponse はトークンエンドポイントのレスポンス DTO。
// refresh_token は Cookie で返すため JSON には含めない。
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
}

// ErrorResponse はエラー時のレスポンス DTO（OAuth 2.0 準拠）。
type ErrorResponse struct {
	Error string `json:"error"`
}
