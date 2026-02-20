package handler

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/request"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/adapter/dto/response"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
)

// parseBasicAuth は Authorization: Basic base64(client_id:client_secret) をパースする。
func parseBasicAuth(auth string) (clientID, clientSecret string, ok bool) {
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// RT Cookie 名（__Host- prefix で強めの制約）
const rtCookieName = "__Host-rt"

// RT Cookie 有効期限（30日、秒）
const rtCookieMaxAge = 30 * 24 * 3600

// TokenHandler はトークンエンドポイントのハンドラ。
type TokenHandler struct {
	tokenUseCase   token.Interactor
	clientRepo     port.ClientRepository
	allowedOrigins []string // CSRF 用（refresh_token の Origin チェック）
}

// NewTokenHandler は TokenHandler を生成する。
func NewTokenHandler(tokenUseCase token.Interactor, clientRepo port.ClientRepository, allowedOrigins []string) *TokenHandler {
	return &TokenHandler{
		tokenUseCase:   tokenUseCase,
		clientRepo:     clientRepo,
		allowedOrigins: allowedOrigins,
	}
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

	// Confidential client: Authorization: Basic で client_secret が渡された場合に検証
	if clientIDStr, clientSecret, ok := parseBasicAuth(c.Request().Header.Get("Authorization")); ok && clientSecret != "" {
		parsedID, parseErr := uuid.Parse(clientIDStr)
		if parseErr != nil || parsedID != clientID {
			c.Response().Header().Set("WWW-Authenticate", "Bearer")
			return c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: "invalid_client"})
		}
		valid, _ := h.clientRepo.ValidateClientCredentials(c.Request().Context(), clientID, clientSecret)
		if !valid {
			c.Response().Header().Set("WWW-Authenticate", "Bearer")
			return c.JSON(http.StatusUnauthorized, response.ErrorResponse{Error: "invalid_client"})
		}
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
	// CSRF 対策: Origin / Referer が許可リストに含まれること（Cookie 送信のため）
	if !h.checkOrigin(c) {
		return c.JSON(http.StatusForbidden, response.ErrorResponse{Error: "invalid_request"})
	}

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

// checkOrigin は Origin または Referer が許可リストに含まれるか確認する（CSRF 対策）。
func (h *TokenHandler) checkOrigin(c echo.Context) bool {
	origin := c.Request().Header.Get("Origin")
	if origin != "" {
		for _, allowed := range h.allowedOrigins {
			if origin == allowed {
				return true
			}
		}
	}
	referer := c.Request().Header.Get("Referer")
	if referer != "" {
		for _, allowed := range h.allowedOrigins {
			if strings.HasPrefix(referer, allowed+"/") || referer == allowed {
				return true
			}
		}
	}
	// 同一オリジン（Origin なし＝同一オリジンリクエスト）は許可
	if origin == "" && referer == "" {
		return true
	}
	return false
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
