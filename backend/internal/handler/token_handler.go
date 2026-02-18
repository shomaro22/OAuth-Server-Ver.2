package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
)

// TokenHandler はトークンエンドポイントのハンドラ。
type TokenHandler struct {
	tokenUseCase *token.UseCase
}

// NewTokenHandler は TokenHandler を生成する。
func NewTokenHandler(tokenUseCase *token.UseCase) *TokenHandler {
	return &TokenHandler{tokenUseCase: tokenUseCase}
}

// Post は認可コードまたはリフレッシュトークンをトークンに交換する。
// POST /token
func (h *TokenHandler) Post(c echo.Context) error {
	grantType := c.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		return h.handleAuthorizationCode(c)
	case "refresh_token":
		return h.handleRefreshToken(c)
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unsupported_grant_type",
		})
	}
}

func (h *TokenHandler) handleAuthorizationCode(c echo.Context) error {
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	clientIDStr := c.FormValue("client_id")
	codeVerifier := c.FormValue("code_verifier")

	if code == "" || redirectURI == "" || clientIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
	}

	out, err := h.tokenUseCase.Exchange(c.Request().Context(), &token.ExchangeInput{
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     clientID,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		switch err {
		case token.ErrInvalidCode, token.ErrInvalidRedirectURI, token.ErrInvalidPKCE:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid_grant",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "server_error",
			})
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  out.AccessToken,
		"token_type":    out.TokenType,
		"expires_in":    out.ExpiresIn,
		"refresh_token": out.RefreshToken,
		"scope":         out.Scope,
	})
}

func (h *TokenHandler) handleRefreshToken(c echo.Context) error {
	refreshToken := c.FormValue("refresh_token")
	clientIDStr := c.FormValue("client_id")

	if refreshToken == "" || clientIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
	}

	out, err := h.tokenUseCase.Refresh(c.Request().Context(), &token.RefreshInput{
		RefreshToken: refreshToken,
		ClientID:     clientID,
	})
	if err != nil {
		switch err {
		case token.ErrInvalidRefreshToken, token.ErrTokenExpired:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid_grant",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "server_error",
			})
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  out.AccessToken,
		"token_type":    out.TokenType,
		"expires_in":    out.ExpiresIn,
		"refresh_token": out.RefreshToken,
		"scope":         out.Scope,
	})
}
