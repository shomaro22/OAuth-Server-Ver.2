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
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/introspect"
)

// IntrospectHandler はトークンイントロスペクトエンドポイントのハンドラ。
type IntrospectHandler struct {
	introspectUseCase introspect.Interactor
	clientRepo        port.ClientRepository
}

// NewIntrospectHandler は IntrospectHandler を生成する。
func NewIntrospectHandler(introspectUseCase introspect.Interactor, clientRepo port.ClientRepository) *IntrospectHandler {
	return &IntrospectHandler{
		introspectUseCase: introspectUseCase,
		clientRepo:        clientRepo,
	}
}

// Post は RFC 7662 トークンイントロスペクトを処理する。
// POST /oauth/introspect
// Authorization: Basic 必須。認証NGは401、入力不正は400、トークン無効は200 {active:false}、サーバ障害は500。
func (h *IntrospectHandler) Post(c echo.Context) error {
	// 1. Client認証（Basic必須）
	clientID, clientSecret, ok := parseBasicAuth(c.Request().Header.Get("Authorization"))
	if !ok || clientID == "" || clientSecret == "" {
		c.Response().Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		return c.JSON(http.StatusUnauthorized, response.IntrospectResponse{Active: false})
	}
	parsedClientID, err := uuid.Parse(clientID)
	if err != nil {
		c.Response().Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		return c.JSON(http.StatusUnauthorized, response.IntrospectResponse{Active: false})
	}
	valid, err := h.clientRepo.ValidateClientCredentials(c.Request().Context(), parsedClientID, clientSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, response.IntrospectResponse{Active: false})
	}
	if !valid {
		c.Response().Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		return c.JSON(http.StatusUnauthorized, response.IntrospectResponse{Active: false})
	}

	// 2. リクエストバインディング
	var req request.IntrospectRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, response.IntrospectResponse{Active: false})
	}
	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, response.IntrospectResponse{Active: false})
	}

	// 3. トークン照合（無効/期限切れ/照合NG → 200 {active:false}）
	out, err := h.introspectUseCase.Introspect(c.Request().Context(), &introspect.IntrospectInput{
		Token:         req.Token,
		TokenTypeHint: req.TokenTypeHint,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, response.IntrospectResponse{Active: false})
	}

	res := response.IntrospectResponse{
		Active:   out.Active,
		Sub:      out.Sub,
		Sid:      out.Sid,
		Ver:      out.Ver,
		Exp:      out.Exp,
		Iat:      out.Iat,
		ClientID: out.ClientID,
		Scope:    out.Scope,
	}
	return c.JSON(http.StatusOK, res)
}

// parseBasicAuth は Authorization: Basic <base64> をパースし client_id, client_secret を返す。
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
