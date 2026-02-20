package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/request"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/response"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/login"
)

// LoginHandler はログイン API のハンドラ。
type LoginHandler struct {
	loginUseCase *login.UseCase
}

// NewLoginHandler は LoginHandler を生成する。
func NewLoginHandler(loginUseCase *login.UseCase) *LoginHandler {
	return &LoginHandler{loginUseCase: loginUseCase}
}

// Post はログインを処理する。
// POST /sessions/login
func (h *LoginHandler) Post(c echo.Context) error {
	var req request.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	out, err := h.loginUseCase.Login(c.Request().Context(), &login.LoginInput{
		LoginChallenge: req.LoginChallenge,
		Username:       req.Username,
		Password:       req.Password,
		IPAddress:      c.RealIP(),
		UserAgent:      c.Request().UserAgent(),
	})
	if err != nil {
		switch err {
		case login.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: "invalid_credentials"})
		case login.ErrChallengeNotFound:
			return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
		default:
			return c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: "server_error"})
		}
	}

	// セッション Cookie をセットする（authorize と共通）
	secure := c.Request().TLS != nil
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    out.SessionToken,
		Path:     "/",
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	return c.JSON(http.StatusOK, response.LoginResponse{
		NextURL: out.NextURL,
	})
}
