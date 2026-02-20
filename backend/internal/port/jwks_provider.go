package port

// JWKSProvider は JWKS（公開鍵セット）を提供するインターフェース。
// handler が infrastructure に直接依存しないように port で定義する。
type JWKSProvider interface {
	ExportJWKS() any
}
