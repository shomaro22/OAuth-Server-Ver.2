package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
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

// authorizeParams は GET/POST 共通の認可リクエストパラメータ。
type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizeHandler は認可エンドポイントのハンドラ。
type AuthorizeHandler struct {
	authorizeUseCase authorize.Interactor
}

// NewAuthorizeHandler は AuthorizeHandler を生成する。
func NewAuthorizeHandler(authorizeUseCase authorize.Interactor) *AuthorizeHandler {
	return &AuthorizeHandler{
		authorizeUseCase: authorizeUseCase,
	}
}

// Get は認可リクエストを処理する（クエリパラメータ検証→ログイン画面表示等）。
// GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...&code_challenge=...&code_challenge_method=S256
func (h *AuthorizeHandler) Get(c echo.Context) error {
	params := parseAuthorizeParams(c, true)
	if err := h.validateAuthorizeParams(c, params); err != nil {
		return err
	}
	// TODO: ログイン画面表示、Consent画面表示（Step 4）
	// 暫定: 検証OKなら approve フォームを表示（POST で code 発行へ）
	return renderApproveForm(c, params)
}

// Post は認可承認を処理し、認可コードを発行してリダイレクトする。
// POST /oauth/authorize
func (h *AuthorizeHandler) Post(c echo.Context) error {
	params := parseAuthorizeParams(c, false)
	if err := h.validateAuthorizeParams(c, params); err != nil {
		return err
	}

	clientID, _ := uuid.Parse(params.ClientID)
	scope := params.Scope
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
		ResponseType:        "code",
		UserID:              testUserID,
		ClientID:            clientID,
		RedirectURI:         params.RedirectURI,
		Scopes:              scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		SessionTokenHash:    sessionTokenHash,
		IPAddress:           c.RealIP(),
		UserAgent:           c.Request().UserAgent(),
	})
	if err != nil {
		return h.authorizeErrorResponse(c, err)
	}

	// redirect_uri?code=...&state=... へ 302 リダイレクト
	u, _ := url.Parse(params.RedirectURI)
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

// parseAuthorizeParams は GET(クエリ) または POST(フォーム) からパラメータを取得する。
func parseAuthorizeParams(c echo.Context, fromQuery bool) authorizeParams {
	if fromQuery {
		return authorizeParams{
			ClientID:            c.QueryParam("client_id"),
			RedirectURI:         c.QueryParam("redirect_uri"),
			ResponseType:        c.QueryParam("response_type"),
			Scope:               c.QueryParam("scope"),
			State:               c.QueryParam("state"),
			Nonce:               c.QueryParam("nonce"),
			CodeChallenge:       c.QueryParam("code_challenge"),
			CodeChallengeMethod: c.QueryParam("code_challenge_method"),
		}
	}
	return authorizeParams{
		ClientID:            c.FormValue("client_id"),
		RedirectURI:         c.FormValue("redirect_uri"),
		ResponseType:        c.FormValue("response_type"),
		Scope:               c.FormValue("scope"),
		State:               c.FormValue("state"),
		Nonce:               c.FormValue("nonce"),
		CodeChallenge:       c.FormValue("code_challenge"),
		CodeChallengeMethod: c.FormValue("code_challenge_method"),
	}
}

// validateAuthorizeParams は params を検証し、NG なら 400 を返す。
func (h *AuthorizeHandler) validateAuthorizeParams(c echo.Context, params authorizeParams) error {
	if params.ClientID == "" || params.RedirectURI == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id and redirect_uri are required",
		})
	}
	clientID, err := uuid.Parse(params.ClientID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "invalid client_id",
		})
	}
	err = h.authorizeUseCase.ValidateAuthorizeRequest(c.Request().Context(), &authorize.ValidateAuthorizeInput{
		ClientID:            clientID,
		RedirectURI:         params.RedirectURI,
		ResponseType:        params.ResponseType,
		Scope:               params.Scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
	})
	if err != nil {
		return h.authorizeErrorResponse(c, err)
	}
	return nil
}

func (h *AuthorizeHandler) authorizeErrorResponse(c echo.Context, err error) error {
	switch err {
	case authorize.ErrInvalidRedirectURI:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "redirect_uri mismatch",
		})
	case authorize.ErrInvalidResponseType:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "response_type must be code",
		})
	case authorize.ErrCodeChallengeRequired:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "code_challenge is required",
		})
	case authorize.ErrStateRequired:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "state is required",
		})
	case authorize.ErrUnsupportedPKCE:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "PKCE: only S256 is supported",
		})
	case authorize.ErrInvalidScope:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "scope is invalid or not allowed for client",
		})
	default:
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
	}
}

// renderApproveForm は検証OK時に approve フォーム（簡易）を返す。
func renderApproveForm(c echo.Context, params authorizeParams) error {
	tmpl := `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Authorize</title></head>
<body>
<h2>Authorize</h2>
<p>Client requests access. Click Approve to continue.</p>
<form method="POST" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="%s">
  <input type="hidden" name="redirect_uri" value="%s">
  <input type="hidden" name="response_type" value="code">
  <input type="hidden" name="scope" value="%s">
  <input type="hidden" name="state" value="%s">
  <input type="hidden" name="nonce" value="%s">
  <input type="hidden" name="code_challenge" value="%s">
  <input type="hidden" name="code_challenge_method" value="%s">
  <button type="submit">Approve</button>
</form>
</body>
</html>`
	return c.HTML(http.StatusOK, fmt.Sprintf(tmpl,
		html.EscapeString(params.ClientID),
		html.EscapeString(params.RedirectURI),
		html.EscapeString(params.Scope),
		html.EscapeString(params.State),
		html.EscapeString(params.Nonce),
		html.EscapeString(params.CodeChallenge),
		html.EscapeString(params.CodeChallengeMethod),
	))
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
