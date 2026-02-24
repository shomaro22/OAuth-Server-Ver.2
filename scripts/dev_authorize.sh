#!/bin/bash
# 開発用: PKCE 生成 → authorize URL 出力 → ブラウザで開く
# 実行: ./scripts/dev_authorize.sh
# 前提: backend + frontend が起動済み

set -e
cd "$(dirname "$0")/.."

REDIRECT_URI="${1:-http://localhost:5173/callback}"
API_BASE="${2:-http://localhost:8080}"
CLIENT_ID="11111111-1111-1111-1111-111111111111"

OUTPUT=$(node backend/scripts/gen_pkce.js "$REDIRECT_URI")
echo "$OUTPUT"

# authorize URL を抽出（gen_pkce.js の出力形式に依存）
URL=$(echo "$OUTPUT" | awk '/authorize URL/{getline; print; exit}' | tr -d '\r\n')
# localhost:8080 を API_BASE のホストに置換
URL="${URL//http:\/\/localhost:8080/$API_BASE}"

echo ""
echo "ブラウザで開く: $URL"

if command -v open &>/dev/null; then
  open "$URL"
elif command -v xdg-open &>/dev/null; then
  xdg-open "$URL"
else
  echo "ブラウザで上記 URL を開いてください"
fi
