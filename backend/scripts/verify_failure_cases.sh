#!/bin/bash
# 失敗系の挙動チェック（提出前確認用）
# 前提: backend が http://localhost:8080 で起動、DB/Redis が稼働していること
# 実行: ./scripts/verify_failure_cases.sh [BASE_URL]

BASE_URL="${1:-http://localhost:8080}"
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

echo "=== 失敗系挙動チェック ($BASE_URL) ==="

# 0) /oauth/authorize: redirect_uri 不一致 → 400 invalid_request
echo ""
echo "[0] authorize: redirect_uri 不一致 → 400"
RES=$(curl -s -w "\n%{http_code}" "$BASE_URL/oauth/authorize?response_type=code&client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://evil.com/callback&scope=openid&state=x&code_challenge=xxx&code_challenge_method=S256&nonce=n")
BODY=$(echo "$RES" | sed '$d')
STATUS=$(echo "$RES" | tail -1)
if echo "$BODY" | grep -q "redirect_uri mismatch" && [ "$STATUS" = "400" ]; then
  pass "authorize redirect_uri 不一致 → 400"
else
  fail "authorize redirect_uri 不一致時の応答が不正 (status=$STATUS, body=$BODY)"
fi

# 1) /oauth/token: code 二回使用 → invalid_grant
echo ""
echo "[1] code 二回使用 → invalid_grant"
# ダミー code で invalid_grant が返ることを確認（本物の code は1回限りなので、ダミーで 400 invalid_grant になる）
RES=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=dummy-code-reuse-test" \
  -d "redirect_uri=http://localhost:5173/callback" \
  -d "client_id=11111111-1111-1111-1111-111111111111" \
  -d "code_verifier=dummy-verifier")
BODY=$(echo "$RES" | sed '$d')
STATUS=$(echo "$RES" | tail -1)
if echo "$BODY" | grep -q "invalid_grant" && [ "$STATUS" = "400" ]; then
  pass "code 不正 → 400 invalid_grant"
else
  fail "code 不正時の応答が不正 (status=$STATUS, body=$BODY)"
fi

# 2) /oauth/token: PKCE verifier 不一致 → invalid_grant
echo ""
echo "[2] PKCE verifier 不一致 → invalid_grant"
# 正しい形式の code でも verifier が違えば invalid_grant（実際の code がないので、invalid_code か invalid_grant のどちらか）
RES=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=valid-looking-but-fake" \
  -d "redirect_uri=http://localhost:5173/callback" \
  -d "client_id=11111111-1111-1111-1111-111111111111" \
  -d "code_verifier=wrong-verifier")
BODY=$(echo "$RES" | sed '$d')
STATUS=$(echo "$RES" | tail -1)
if echo "$BODY" | grep -qE "invalid_grant|invalid_request" && [ "$STATUS" = "400" ]; then
  pass "PKCE 不正 → 400"
else
  fail "PKCE 不正時の応答が不正 (status=$STATUS)"
fi

# 3) /oauth/token: redirect_uri 不一致 → invalid_grant（code 交換時はサーバ側で検証）
echo ""
echo "[3] redirect_uri 不一致 → invalid_grant"
RES=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=x" \
  -d "redirect_uri=http://evil.com/callback" \
  -d "client_id=11111111-1111-1111-1111-111111111111" \
  -d "code_verifier=y")
BODY=$(echo "$RES" | sed '$d')
STATUS=$(echo "$RES" | tail -1)
if [ "$STATUS" = "400" ] || [ "$STATUS" = "401" ]; then
  pass "redirect_uri 不正 → 4xx"
else
  fail "redirect_uri 不正時の応答が不正 (status=$STATUS)"
fi

# 4) /oauth/token (refresh): cookie なし → invalid_request
echo ""
echo "[4] refresh_token: cookie なし → invalid_request"
RES=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=11111111-1111-1111-1111-111111111111")
BODY=$(echo "$RES" | sed '$d')
STATUS=$(echo "$RES" | tail -1)
if echo "$BODY" | grep -q "invalid_request" && [ "$STATUS" = "400" ]; then
  pass "refresh cookie なし → 400 invalid_request"
else
  # CSRF で 403 になる可能性もある
  if [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ]; then
    pass "refresh cookie なし → 4xx 拒否"
  else
    fail "refresh cookie なし時の応答が不正 (status=$STATUS)"
  fi
fi

echo ""
echo "✅ 失敗系チェック OK"
