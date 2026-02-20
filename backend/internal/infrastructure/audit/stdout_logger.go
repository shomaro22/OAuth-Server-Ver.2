package audit

import (
	"context"
	"log"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.AuditLogger = (*StdoutLogger)(nil)

// StdoutLogger は監査ログを標準出力に出力する（開発用）。
type StdoutLogger struct{}

// NewStdoutLogger は StdoutLogger を生成する。
func NewStdoutLogger() *StdoutLogger {
	return &StdoutLogger{}
}

// Log は監査ログを出力する。
func (l *StdoutLogger) Log(ctx context.Context, entry *port.AuditEntry) {
	if entry == nil {
		return
	}
	log.Printf("[AUDIT] event=%s user_id=%s client_id=%s session_id=%s jti=%s ip=%s user_agent=%s",
		entry.Event,
		entry.UserID.String(),
		entry.ClientID.String(),
		entry.SessionID.String(),
		entry.JTI,
		entry.IP,
		entry.UserAgent,
	)
}
