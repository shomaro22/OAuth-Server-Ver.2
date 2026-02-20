package authorize

import "context"

// Interactor は認可コード発行のユースケースインターフェース。
// 責務：code 生成、authcode 保存、redirect URI 作成。セッションは触らない。
type Interactor interface {
	ValidateAuthorizeRequest(ctx context.Context, in *ValidateAuthorizeInput) error
	CreateLoginChallenge(ctx context.Context, params *StoredAuthParams) (challenge, redirectURL string, err error)
	GetChallenge(ctx context.Context, challenge string) (*StoredAuthParams, error)
	GetAndConsumeChallenge(ctx context.Context, challenge string) (*StoredAuthParams, error)
	ConsumeChallenge(ctx context.Context, challenge string) error
	IssueCode(ctx context.Context, in *IssueCodeInput) (*IssueCodeOutput, error)
}
