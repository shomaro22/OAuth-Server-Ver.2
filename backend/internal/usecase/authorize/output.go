package authorize

// IssueCodeOutput は認可コード発行の出力。
type IssueCodeOutput struct {
	Code        string
	RedirectURI string
	State       string
}
