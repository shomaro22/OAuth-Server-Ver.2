package request

// IntrospectRequest は RFC 7662 トークンイントロスペクトのリクエスト DTO。
// POST body は application/x-www-form-urlencoded。
type IntrospectRequest struct {
	Token         string `form:"token" validate:"required"`
	TokenTypeHint string `form:"token_type_hint"` // "access_token" | "refresh_token" | ""
}
