package handler

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

// sessionCookieName は /sessions/login でセットする Cookie 名（login_handler と共通）
const sessionCookieName = "oauth_session"

// sessionMaxAge はセッション Cookie の有効期限（秒）。login_handler で使用。
const sessionMaxAge = 24 * 60 * 60

// authorizeParams は GET の認可リクエストパラメータ。
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

// SessionResolver はセッション解決のインターフェース（authorize は code 発行のみのため分離）。
type SessionResolver interface {
	Resolve(ctx context.Context, sessionToken string) (sessionID, userID uuid.UUID, ok bool, err error)
}

// AuthorizeHandler は認可エンドポイントのハンドラ。
// 責務：request validation、セッションCookie確認、なければ login へ redirect、あれば IssueCode。
type AuthorizeHandler struct {
	authorizeUseCase authorize.Interactor
	sessionResolver  SessionResolver
	loginURL         string
	serverBaseURL    string
}

// NewAuthorizeHandler は AuthorizeHandler を生成する。
func NewAuthorizeHandler(authorizeUseCase authorize.Interactor, sessionResolver SessionResolver, loginURL, serverBaseURL string) *AuthorizeHandler {
	return &AuthorizeHandler{
		authorizeUseCase: authorizeUseCase,
		sessionResolver:  sessionResolver,
		loginURL:         loginURL,
		serverBaseURL:    serverBaseURL,
	}
}

// Get は認可リクエストを処理する。
// ログイン済みなら code 発行→redirect。未ログインなら login_challenge 発行して React へリダイレクト。
// GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...&code_challenge=...&code_challenge_method=S256
func (h *AuthorizeHandler) Get(c echo.Context) error {
	params := parseAuthorizeParams(c)
	if err := h.validateAuthorizeParams(c, params); err != nil {
		return err
	}

	sessionToken := ""
	if cookie, err := c.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		sessionToken = cookie.Value
	}
	sessionID, userID, ok, err := h.sessionResolver.Resolve(c.Request().Context(), sessionToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	if ok && sessionID != uuid.Nil && userID != uuid.Nil {
		// ログイン済み → code 発行して redirect（approve フォームなし）
		clientID, _ := uuid.Parse(params.ClientID)
		scope := params.Scope
		if scope == "" {
			scope = "openid"
		}
		out, err := h.authorizeUseCase.IssueCode(c.Request().Context(), &authorize.IssueCodeInput{
			ResponseType:        "code",
			UserID:              userID,
			SessionID:           sessionID,
			ClientID:            clientID,
			RedirectURI:         params.RedirectURI,
			Scopes:              scope,
			State:               params.State,
			Nonce:               params.Nonce,
			CodeChallenge:       params.CodeChallenge,
			CodeChallengeMethod: params.CodeChallengeMethod,
		})
		if err != nil {
			return h.authorizeErrorResponse(c, err)
		}
		u, _ := url.Parse(params.RedirectURI)
		q := u.Query()
		q.Set("code", out.Code)
		if out.State != "" {
			q.Set("state", out.State)
		}
		u.RawQuery = q.Encode()
		return c.Redirect(http.StatusFound, u.String())
	}

	// 未ログイン → login_challenge 発行して React へリダイレクト
	_, redirectURL, err := h.authorizeUseCase.CreateLoginChallenge(c.Request().Context(), &authorize.StoredAuthParams{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		ResponseType:        params.ResponseType,
		Scope:               params.Scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		LoginURL:            h.loginURL,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return c.Redirect(http.StatusFound, redirectURL)
}

// GetContinue はログイン後の認可リクエスト再開を処理する。
// GET /oauth/authorize/continue?login_challenge=...
func (h *AuthorizeHandler) GetContinue(c echo.Context) error {
	challenge := c.QueryParam("login_challenge")
	if challenge == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "login_challenge is required",
		})
	}

	sessionToken := ""
	if cookie, err := c.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		sessionToken = cookie.Value
	}
	sessionID, userID, ok, err := h.sessionResolver.Resolve(c.Request().Context(), sessionToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	if !ok || sessionID == uuid.Nil || userID == uuid.Nil {
		redirectURL := h.loginURL + "?login_challenge=" + challenge
		return c.Redirect(http.StatusFound, redirectURL)
	}

	stored, err := h.authorizeUseCase.GetAndConsumeChallenge(c.Request().Context(), challenge)
	if err != nil {
		if errors.Is(err, authorize.ErrChallengeNotFound) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "login challenge not found or expired",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	clientID, _ := uuid.Parse(stored.ClientID)
	scope := stored.Scope
	if scope == "" {
		scope = "openid"
	}

	out, err := h.authorizeUseCase.IssueCode(c.Request().Context(), &authorize.IssueCodeInput{
		ResponseType:        "code",
		UserID:             userID,
		SessionID:          sessionID,
		ClientID:           clientID,
		RedirectURI:        stored.RedirectURI,
		Scopes:             scope,
		State:              stored.State,
		Nonce:              stored.Nonce,
		CodeChallenge:     stored.CodeChallenge,
		CodeChallengeMethod: stored.CodeChallengeMethod,
	})
	if err != nil {
		return h.authorizeErrorResponse(c, err)
	}

	u, _ := url.Parse(stored.RedirectURI)
	q := u.Query()
	q.Set("code", out.Code)
	if out.State != "" {
		q.Set("state", out.State)
	}
	u.RawQuery = q.Encode()

	return c.Redirect(http.StatusFound, u.String())
}

func parseAuthorizeParams(c echo.Context) authorizeParams {
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

// clearSessionCookie はログアウト時にセッション cookie を削除する（将来の logout 用）。
func clearSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}
