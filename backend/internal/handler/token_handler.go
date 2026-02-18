package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/request"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/response"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
)

// RT Cookie 名（__Host- prefix で強めの制約）
const rtCookieName = "__Host-rt"

// RT Cookie 有効期限（30日、秒）
const rtCookieMaxAge = 30 * 24 * 3600

// TokenHandler はトークンエンドポイントのハンドラ。
type TokenHandler struct {
	tokenUseCase token.Interactor
}

// NewTokenHandler は TokenHandler を生成する。
func NewTokenHandler(tokenUseCase token.Interactor) *TokenHandler {
	return &TokenHandler{tokenUseCase: tokenUseCase}
}

// Post は認可コードまたはリフレッシュトークンをトークンに交換する。
// POST /oauth/token
func (h *TokenHandler) Post(c echo.Context) error {
	var grantReq struct {
		GrantType string `form:"grant_type"`
	}
	if err := c.Bind(&grantReq); err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}
	switch grantReq.GrantType {
	case "authorization_code":
		return h.handleAuthorizationCode(c)
	case "refresh_token":
		return h.handleRefreshToken(c)
	default:
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "unsupported_grant_type"})
	}
}

func (h *TokenHandler) handleAuthorizationCode(c echo.Context) error {
	var req request.AuthCodeTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}
	if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}
	// PKCE S256 only: code_verifier 必須
	if req.CodeVerifier == "" {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	out, err := h.tokenUseCase.Exchange(c.Request().Context(), &token.ExchangeInput{
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		ClientID:     clientID,
		CodeVerifier: req.CodeVerifier,
	})
	if err != nil {
		switch err {
		case token.ErrInvalidClient:
			c.Response().Header().Set("WWW-Authenticate", "Bearer")
			return c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: "invalid_client"})
		case token.ErrInvalidCode, token.ErrInvalidRedirectURI, token.ErrInvalidPKCE:
			return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_grant"})
		default:
			return c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: "server_error"})
		}
	}

	// refresh_token を Cookie で返却（body には含めない）
	setRefreshTokenCookie(c, out.RefreshToken)

	return c.JSON(http.StatusOK, response.TokenResponse{
		AccessToken: out.AccessToken,
		TokenType:   out.TokenType,
		ExpiresIn:   out.ExpiresIn,
		Scope:       out.Scope,
		IDToken:     out.IDToken,
	})
}

func (h *TokenHandler) handleRefreshToken(c echo.Context) error {
	// refresh_token は Cookie から取得（body には含めない）
	refreshToken := ""
	if cookie, err := c.Cookie(rtCookieName); err == nil && cookie != nil {
		refreshToken = cookie.Value
	}
	if refreshToken == "" {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	var req request.RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}
	if req.ClientID == "" {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_request"})
	}

	out, err := h.tokenUseCase.Refresh(c.Request().Context(), &token.RefreshInput{
		RefreshToken: refreshToken,
		ClientID:     clientID,
	})
	if err != nil {
		switch err {
		case token.ErrInvalidRefreshToken, token.ErrTokenExpired:
			return c.JSON(http.StatusBadRequest, response.ErrorResponse{Error: "invalid_grant"})
		default:
			return c.JSON(http.StatusInternalServerError, response.ErrorResponse{Error: "server_error"})
		}
	}

	// 新 RT を Cookie で返却（rotation 後）
	setRefreshTokenCookie(c, out.RefreshToken)

	return c.JSON(http.StatusOK, response.TokenResponse{
		AccessToken: out.AccessToken,
		TokenType:   out.TokenType,
		ExpiresIn:   out.ExpiresIn,
		Scope:       out.Scope,
		IDToken:     out.IDToken,
	})
}

// setRefreshTokenCookie は refresh_token を HttpOnly Cookie で設定する。
func setRefreshTokenCookie(c echo.Context, rt string) {
	cookie := &http.Cookie{
		Name:     rtCookieName,
		Value:    rt,
		Path:     "/",
		MaxAge:   rtCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)
}
