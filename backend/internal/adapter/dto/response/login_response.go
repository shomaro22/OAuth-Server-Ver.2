package response

// LoginResponse はログイン成功時のレスポンス DTO。
type LoginResponse struct {
	NextURL string `json:"next_url"`
}
