#!/bin/bash
# ID Token の iss / kid 整合チェック（自動化）
# 前提: backend 起動、token 交換で id_token を取得済み
# 実行: ./scripts/verify_id_token.sh [BASE_URL] [ID_TOKEN]
# ID_TOKEN 省略時は、E2E フローで取得した token を環境変数 ID_TOKEN から読む

set -e
BASE_URL="${1:-http://localhost:8080}"
ID_TOKEN="${2:-$ID_TOKEN}"

if [ -z "$ID_TOKEN" ]; then
  echo "Usage: $0 [BASE_URL] [ID_TOKEN]"
  echo "  or: ID_TOKEN=xxx $0 [BASE_URL]"
  echo ""
  echo "ID Token 取得例（gen_pkce.js で code 取得後）:"
  echo "  curl -s -X POST $BASE_URL/oauth/token -d grant_type=authorization_code -d code=... -d redirect_uri=... -d client_id=... -d code_verifier=... | jq -r .id_token"
  exit 1
fi

# JWT を . で分割（header.payload.signature）
HEADER_B64=$(echo "$ID_TOKEN" | cut -d. -f1)
PAYLOAD_B64=$(echo "$ID_TOKEN" | cut -d. -f2)

# base64url デコード（パディング補正）
decode_base64url() {
  local s="$1"
  local rem=$(( ${#s} % 4 ))
  [ $rem -eq 2 ] && s="${s}=="
  [ $rem -eq 3 ] && s="${s}="
  echo "$s" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "$s" | tr '_-' '/+' | base64 -D 2>/dev/null
}

HEADER_JSON=$(decode_base64url "$HEADER_B64")
PAYLOAD_JSON=$(decode_base64url "$PAYLOAD_B64")

# issuer 取得（payload）
ISSUER=$(echo "$PAYLOAD_JSON" | grep -o '"iss":"[^"]*"' | cut -d'"' -f4)
# kid 取得（header）
KID=$(echo "$HEADER_JSON" | grep -o '"kid":"[^"]*"' | cut -d'"' -f4)

# Discovery から issuer 取得
DISC_ISSUER=$(curl -s "$BASE_URL/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)
# JWKS から kid 取得
JWKS_KID=$(curl -s "$BASE_URL/jwks" | grep -o '"kid":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "=== ID Token 整合チェック ==="
echo "  id_token.iss:  $ISSUER"
echo "  discovery.issuer: $DISC_ISSUER"
echo "  id_token.kid:  $KID"
echo "  jwks.kid:      $JWKS_KID"

FAIL=0
if [ "$ISSUER" != "$DISC_ISSUER" ]; then
  echo "❌ iss 不一致"
  FAIL=1
fi
if [ "$KID" != "$JWKS_KID" ]; then
  echo "❌ kid 不一致"
  FAIL=1
fi

if [ $FAIL -eq 0 ]; then
  echo ""
  echo "✅ ID Token iss / kid 整合 OK"
fi
exit $FAIL
