package introspect

// IntrospectInput はトークンイントロスペクトの入力。
type IntrospectInput struct {
	Token         string // 必須
	TokenTypeHint string // "access_token" | "refresh_token" | ""
}
