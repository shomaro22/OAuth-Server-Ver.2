package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

// AuthorizeHandler は認可エンドポイントのハンドラ。
type AuthorizeHandler struct {
	authorizeUseCase *authorize.UseCase
}

// NewAuthorizeHandler は AuthorizeHandler を生成する。
func NewAuthorizeHandler(authorizeUseCase *authorize.UseCase) *AuthorizeHandler {
	return &AuthorizeHandler{
		authorizeUseCase: authorizeUseCase,
	}
}

// Get は認可リクエストを処理する（ログイン画面表示等）。
// GET /authorize
func (h *AuthorizeHandler) Get(c echo.Context) error {
	// TODO: ログイン画面表示、Consent画面表示
	return c.JSON(http.StatusOK, map[string]string{
		"message": "authorize GET - login/consent UI",
	})
}

// Post は認可承認を処理し、認可コードを発行してリダイレクトする。
// POST /authorize
func (h *AuthorizeHandler) Post(c echo.Context) error {
	// TODO: 認可承認後、IssueCode 呼び出し、redirect_uri へリダイレクト
	_ = h.authorizeUseCase
	return c.JSON(http.StatusOK, map[string]string{
		"message": "authorize POST - code issuance",
	})
}
