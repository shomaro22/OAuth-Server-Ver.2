package authorize

import "github.com/google/uuid"

// IssueCodeInput は認可コード発行の入力。
type IssueCodeInput struct {
	UserID              uuid.UUID
	ClientID            uuid.UUID
	RedirectURI         string
	Scopes              string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionTokenHash    string
	IPAddress           string
	UserAgent           string
}
