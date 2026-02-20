package request

// LoginRequest はログイン API のリクエスト DTO。
type LoginRequest struct {
	LoginChallenge string `json:"login_challenge"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}
