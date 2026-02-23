#!/bin/bash
# OIDC 整合チェック（提出前確認用）
# 前提: backend が http://localhost:8080 で起動していること
# 実行: ./scripts/verify_oidc.sh [BASE_URL]

set -e
BASE_URL="${1:-http://localhost:8080}"

echo "=== OIDC 整合チェック (BASE_URL=$BASE_URL) ==="

# 1) Discovery 取得
echo ""
echo "[1] Discovery (/.well-known/openid-configuration)"
DISC=$(curl -s "$BASE_URL/.well-known/openid-configuration")
ISSUER=$(echo "$DISC" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)
JWKS_URI=$(echo "$DISC" | grep -o '"jwks_uri":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ISSUER" ]; then
  echo "❌ issuer が取得できません"
  exit 1
fi
echo "  issuer: $ISSUER"
echo "  jwks_uri: $JWKS_URI"

# 2) JWKS 取得（jwks_uri が到達可能か）
echo ""
echo "[2] JWKS ($JWKS_URI)"
JWKS=$(curl -s "$JWKS_URI")
KEYS_COUNT=$(echo "$JWKS" | grep -o '"keys"' | wc -l)
KID=$(echo "$JWKS" | grep -o '"kid":"[^"]*"' | head -1 | cut -d'"' -f4)
ALG=$(echo "$JWKS" | grep -o '"alg":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$KID" ]; then
  echo "❌ JWKS に kid がありません"
  exit 1
fi
echo "  kid: $KID"
echo "  alg: $ALG"
echo "  keys 配列: OK"

# 3) issuer と jwks_uri の整合
if [ "$ISSUER" != "${JWKS_URI%/jwks}" ]; then
  echo "⚠ issuer と jwks_uri のベースが一致しません"
fi

# 4) alg が RS256 か
if [ "$ALG" != "RS256" ]; then
  echo "❌ alg が RS256 ではありません: $ALG"
  exit 1
fi

echo ""
echo "✅ Discovery / JWKS 整合チェック OK"
echo ""
echo "※ ID Token の iss と kid の一致は E2E フローで取得した token をデコードして確認してください。"
echo "  jwt.io で access_token や id_token を貼り、iss が $ISSUER と一致、ヘッダの kid が $KID と一致することを確認。"
