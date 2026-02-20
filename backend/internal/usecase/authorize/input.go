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
// セッションは /sessions/login で作成済みであること。SessionID は authcode に紐づける。
type IssueCodeInput struct {
	ResponseType        string // "code" 固定
	UserID              uuid.UUID
	SessionID           uuid.UUID // ログイン済みセッション（/sessions/login で作成）
	ClientID            uuid.UUID
	RedirectURI         string
	Scopes              string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}
