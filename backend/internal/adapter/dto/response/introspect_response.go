package response

// IntrospectResponse は RFC 7662 準拠のトークンイントロスペクト応答 DTO。
type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub,omitempty"`
	Sid      string `json:"sid,omitempty"`
	Ver      int64  `json:"ver,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}
