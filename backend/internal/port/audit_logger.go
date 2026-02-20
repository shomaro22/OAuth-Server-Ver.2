package port

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AuditEvent は監査ログのイベント種別。
type AuditEvent string

const (
	AuditAuthorizeRequest AuditEvent = "authorize_request"
	AuditTokenIssued      AuditEvent = "token_issued"
	AuditRefresh          AuditEvent = "refresh"
	AuditLogout           AuditEvent = "logout"
	AuditReuseDetected    AuditEvent = "reuse_detected"
)

// AuditEntry は監査ログの1エントリ。
type AuditEntry struct {
	Event     AuditEvent
	UserID    uuid.UUID
	ClientID  uuid.UUID
	SessionID uuid.UUID
	JTI       string
	IP        string
	UserAgent string
	Timestamp time.Time
}

// AuditLogger は監査ログの出力インターフェース。
type AuditLogger interface {
	Log(ctx context.Context, entry *AuditEntry)
}
