package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

const (
	sessionCookieName = "oauth_session"
	sessionMaxAge     = 24 * 60 * 60 // 24時間（秒）
)

// テスト用固定ユーザーID（UI実装前の暫定）
var testUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

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
// GET /oauth/authorize
func (h *AuthorizeHandler) Get(c echo.Context) error {
	// TODO: ログイン画面表示、Consent画面表示
	return c.JSON(http.StatusOK, map[string]string{
		"message": "authorize GET - login/consent UI",
	})
}

// Post は認可承認を処理し、認可コードを発行してリダイレクトする。
// POST /oauth/authorize
func (h *AuthorizeHandler) Post(c echo.Context) error {
	clientIDStr := c.FormValue("client_id")
	redirectURI := c.FormValue("redirect_uri")
	scope := c.FormValue("scope")
	state := c.FormValue("state")
	codeChallenge := c.FormValue("code_challenge")
	codeChallengeMethod := c.FormValue("code_challenge_method")

	if clientIDStr == "" || redirectURI == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id and redirect_uri are required",
		})
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid client_id",
		})
	}

	// スコープ未指定時は openid をデフォルト
	if scope == "" {
		scope = "openid"
	}

	// セッショントークン：cookie から取得、なければ新規生成（平文は保存せずハッシュのみDB保存）
	sessionTokenHash := ""
	if cookie, err := c.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		sessionTokenHash = hashString(cookie.Value)
	}
	if sessionTokenHash == "" {
		token, err := generateSecureToken()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "server_error",
			})
		}
		sessionTokenHash = hashString(token)

		// HttpOnly + Secure（ローカルは TLS なしなので Secure は off）
		secure := c.Request().TLS != nil
		c.SetCookie(&http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   sessionMaxAge,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	out, err := h.authorizeUseCase.IssueCode(c.Request().Context(), &authorize.IssueCodeInput{
		UserID:              testUserID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		SessionTokenHash:    sessionTokenHash,
		IPAddress:           c.RealIP(),
		UserAgent:           c.Request().UserAgent(),
	})
	if err != nil {
		if err == authorize.ErrInvalidRedirectURI {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid_request",
				"error_description": "redirect_uri mismatch",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
	}

	// redirect_uri?code=...&state=... へ 302 リダイレクト
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", out.Code)
	if out.State != "" {
		q.Set("state", out.State)
	}
	u.RawQuery = q.Encode()

	return c.Redirect(http.StatusFound, u.String())
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// clearSessionCookie はログアウト時にセッション cookie を削除する。
func clearSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}
