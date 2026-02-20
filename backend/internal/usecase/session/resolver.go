package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Resolver はセッションの解決のみを行う（作成・更新はしない）。
// /oauth/authorize の「ログイン済みか？」判定に使用。
type Resolver struct {
	sessionRepo port.SessionRepository
}

// NewResolver は Resolver を生成する。
func NewResolver(sessionRepo port.SessionRepository) *Resolver {
	return &Resolver{sessionRepo: sessionRepo}
}

// Resolve は sessionToken（Cookie の平文）から有効なセッションを取得し、sessionID と userID を返す。
func (r *Resolver) Resolve(ctx context.Context, sessionToken string) (sessionID, userID uuid.UUID, ok bool, err error) {
	if sessionToken == "" {
		return uuid.Nil, uuid.Nil, false, nil
	}
	tokenHash := hashString(sessionToken)
	sess, err := r.sessionRepo.FindBySessionTokenHash(ctx, tokenHash)
	if err != nil || sess == nil {
		return uuid.Nil, uuid.Nil, false, err
	}
	if !sess.IsValid(time.Now()) {
		return uuid.Nil, uuid.Nil, false, nil
	}
	return sess.ID(), sess.UserID(), true, nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
