package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/logout"
)

// LogoutHandler はログアウトエンドポイントのハンドラ。
type LogoutHandler struct {
	logoutUseCase *logout.UseCase
}

// NewLogoutHandler は LogoutHandler を生成する。
func NewLogoutHandler(logoutUseCase *logout.UseCase) *LogoutHandler {
	return &LogoutHandler{logoutUseCase: logoutUseCase}
}

// Post はログアウトを実行する（cookie の oauth_session でこの端末のセッションを失効）。
// POST /oauth/logout
func (h *LogoutHandler) Post(c echo.Context) error {
	cookie, err := c.Cookie(sessionCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "logged out",
		})
	}

	sessionTokenHash := hashString(cookie.Value)

	err = h.logoutUseCase.Logout(c.Request().Context(), &logout.LogoutInput{
		SessionTokenHash: sessionTokenHash,
	})
	if err != nil {
		if err == logout.ErrSessionNotFound {
			// セッションがなければログアウト済み扱い
			clearSessionCookie(c)
			return c.JSON(http.StatusOK, map[string]string{
				"message": "logged out",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
	}

	// ログアウト成功時は cookie を削除
	clearSessionCookie(c)
	return c.JSON(http.StatusOK, map[string]string{
		"message": "logged out",
	})
}
