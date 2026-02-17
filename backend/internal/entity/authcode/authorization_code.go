package authcode

import (
	"time"

	"github.com/google/uuid"
)

// CodeChallengeMethod PKCEのコードチャレンジ方式
const (
	CodeChallengeMethodS256 = "S256"
	CodeChallengeMethodPlain = "plain"
)

// AuthorizationCode は認可コードのドメインエンティティ。
// PKCE、有効期限、再利用防止をサポートする。
type AuthorizationCode struct {
	id                 uuid.UUID
	userID             uuid.UUID
	clientID           uuid.UUID
	codeHash           string
	codeChallenge       string // PKCE: code_verifier から生成した challenge
	codeChallengeMethod string // PKCE: S256 または plain
	redirectURI        string
	scopes             string
	expiresAt          time.Time
	consumed           bool
	createdAt          time.Time
}

// New は新しい AuthorizationCode を作成する。
func New(
	userID uuid.UUID,
	clientID uuid.UUID,
	codeHash string,
	codeChallenge string,
	codeChallengeMethod string,
	redirectURI string,
	scopes string,
	expiresAt time.Time,
) *AuthorizationCode {
	return &AuthorizationCode{
		id:                  uuid.New(),
		userID:              userID,
		clientID:            clientID,
		codeHash:            codeHash,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		redirectURI:         redirectURI,
		scopes:              scopes,
		expiresAt:           expiresAt,
		consumed:            false,
		createdAt:           time.Now(),
	}
}

// ID は認可コードIDを返す。
func (a *AuthorizationCode) ID() uuid.UUID {
	return a.id
}

// UserID はユーザーIDを返す。
func (a *AuthorizationCode) UserID() uuid.UUID {
	return a.userID
}

// ClientID はクライアントIDを返す。
func (a *AuthorizationCode) ClientID() uuid.UUID {
	return a.clientID
}

// CodeHash はコードのハッシュを返す。
func (a *AuthorizationCode) CodeHash() string {
	return a.codeHash
}

// CodeChallenge はPKCEのコードチャレンジを返す。
func (a *AuthorizationCode) CodeChallenge() string {
	return a.codeChallenge
}

// CodeChallengeMethod はPKCEのコードチャレンジ方式を返す。
func (a *AuthorizationCode) CodeChallengeMethod() string {
	return a.codeChallengeMethod
}

// RedirectURI はリダイレクトURIを返す。
func (a *AuthorizationCode) RedirectURI() string {
	return a.redirectURI
}

// Scopes は付与されたスコープを返す。
func (a *AuthorizationCode) Scopes() string {
	return a.scopes
}

// ExpiresAt は有効期限を返す。
func (a *AuthorizationCode) ExpiresAt() time.Time {
	return a.expiresAt
}

// IsExpired は有効期限切れかどうかを判定する。
func (a *AuthorizationCode) IsExpired(now time.Time) bool {
	return now.After(a.expiresAt)
}

// IsConsumed は消費済み（再利用済み）かどうかを判定する。
func (a *AuthorizationCode) IsConsumed() bool {
	return a.consumed
}

// Consume は認可コードを消費する。再利用防止のため1回のみ呼び出し可能。
func (a *AuthorizationCode) Consume() {
	a.consumed = true
}

// IsValid は認可コードが有効かどうかを判定する。
// 有効期限切れまたは消費済みの場合は false。
func (a *AuthorizationCode) IsValid(now time.Time) bool {
	return !a.IsExpired(now) && !a.IsConsumed()
}

// Reconstruct は永続化層から復元するためのファクトリ。
func Reconstruct(
	id uuid.UUID,
	userID uuid.UUID,
	clientID uuid.UUID,
	codeHash string,
	codeChallenge string,
	codeChallengeMethod string,
	redirectURI string,
	scopes string,
	expiresAt time.Time,
	consumed bool,
	createdAt time.Time,
) *AuthorizationCode {
	return &AuthorizationCode{
		id:                  id,
		userID:              userID,
		clientID:            clientID,
		codeHash:            codeHash,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		redirectURI:         redirectURI,
		scopes:              scopes,
		expiresAt:           expiresAt,
		consumed:            consumed,
		createdAt:           createdAt,
	}
}
