package port

import (
	"context"
	"time"
)

// StoredAuthorizationRequest は login_challenge に紐づいて Redis に保存する認可リクエスト。
type StoredAuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string // login, consent, none
}

// AuthorizationRequestRepository は認可リクエストの一時保存（login_challenge 用）。
type AuthorizationRequestRepository interface {
	Save(ctx context.Context, challenge string, req *StoredAuthorizationRequest, ttl time.Duration) error
	Get(ctx context.Context, challenge string) (*StoredAuthorizationRequest, error)
	Delete(ctx context.Context, challenge string) error
}
