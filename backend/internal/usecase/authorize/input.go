package authorize

import "github.com/google/uuid"

// ValidateAuthorizeInput は認可リクエスト検証の入力（GET/POST 共通）。
type ValidateAuthorizeInput struct {
	ClientID            uuid.UUID
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// IssueCodeInput は認可コード発行の入力。
type IssueCodeInput struct {
	ResponseType        string // "code" 固定
	UserID              uuid.UUID
	ClientID            uuid.UUID
	RedirectURI         string
	Scopes              string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionTokenHash    string
	IPAddress           string
	UserAgent           string
}
