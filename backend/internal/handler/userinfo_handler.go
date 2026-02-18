package handler

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/userinfo"
)

// UserInfoHandler はユーザー情報エンドポイントのハンドラ。
type UserInfoHandler struct {
	userInfoUseCase userinfo.Interactor
}

// NewUserInfoHandler は UserInfoHandler を生成する。
func NewUserInfoHandler(userInfoUseCase userinfo.Interactor) *UserInfoHandler {
	return &UserInfoHandler{userInfoUseCase: userInfoUseCase}
}

// Get はアクセストークンからユーザー情報を取得する。
// GET /userinfo
func (h *UserInfoHandler) Get(c echo.Context) error {
	auth := c.Request().Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid_token",
		})
	}
	accessToken := strings.TrimPrefix(auth, "Bearer ")

	out, err := h.userInfoUseCase.Get(c.Request().Context(), &userinfo.GetInput{
		AccessToken: accessToken,
	})
	if err != nil {
		if err == userinfo.ErrInvalidToken {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid_token",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
	}

	return c.JSON(http.StatusOK, out)
}
