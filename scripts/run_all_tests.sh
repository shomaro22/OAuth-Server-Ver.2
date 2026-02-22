#!/bin/bash
# 提出前テスト一括実行（仕様準拠・品質・性能・セキュリティ）
# 実行: ./scripts/run_all_tests.sh [BASE_URL]
# BASE_URL 省略時は http://localhost:8080（事前に backend 起動のこと）

set -e
cd "$(dirname "$0")/.."
BASE_URL="${1:-http://localhost:8080}"
EVIDENCE="backend/tests/evidence"
mkdir -p "$EVIDENCE"/{unit,integration,e2e,load,security,config}

echo "=== 提出前テスト一括実行 (BASE_URL=$BASE_URL) ==="

# 0) Unit + Coverage
echo ""
echo "[1] Unit テスト + Coverage"
cd backend
go test ./... -count=1 -coverprofile=tests/evidence/unit/coverage.out 2>&1 | tee tests/evidence/unit/unit.log
go tool cover -func=tests/evidence/unit/coverage.out 2>&1 | tee tests/evidence/unit/coverage_func.txt
go tool cover -html=tests/evidence/unit/coverage.out -o tests/evidence/unit/coverage.html 2>/dev/null || true
TOTAL=$(go tool cover -func=tests/evidence/unit/coverage.out | awk '/total:/{gsub(/%/,"");print $3}')
echo "Coverage total (全パッケージ): ${TOTAL}%"

# Core Unit Coverage（80%必達）: usecase / handler / jwt のみ（Clean Architecture のビジネスルール＋境界）
echo ""
echo "[1a] Core Unit Coverage（対象: usecase / handler / jwt）"
go test ./internal/usecase/... ./internal/handler/... ./internal/infrastructure/jwt/... \
  -count=1 -coverprofile=tests/evidence/unit/coverage_core.out \
  -coverpkg=./internal/usecase/...,./internal/handler/...,./internal/infrastructure/jwt/... 2>&1 | tee tests/evidence/unit/core_unit.log
go tool cover -func=tests/evidence/unit/coverage_core.out 2>&1 | tee tests/evidence/unit/coverage_core_func.txt
CORE_TOTAL=$(go tool cover -func=tests/evidence/unit/coverage_core.out 2>/dev/null | awk '/^total:/{gsub(/%/,"");print $3}')
[ -n "$CORE_TOTAL" ] && echo "Core Coverage: ${CORE_TOTAL}%"
if [ -n "$CORE_TOTAL" ] && awk -v t="$CORE_TOTAL" 'BEGIN{exit !(t>=80)}' 2>/dev/null; then
  echo "  ✓ Core 80% 以上（要項達成）"
else
  echo "  ⚠ Core 80% 未満（目標: 80%）"
fi

# Entity Coverage（参考）: 値オブジェクトは補助指標
echo ""
echo "[1b] Entity Coverage（参考）"
go test ./internal/entity/... -count=1 -coverprofile=tests/evidence/unit/coverage_entity.out 2>/dev/null || true
ENTITY_TOTAL=$(go tool cover -func=tests/evidence/unit/coverage_entity.out 2>/dev/null | awk '/^total:/{gsub(/%/,"");print $3}')
[ -n "$ENTITY_TOTAL" ] && echo "Entity Coverage: ${ENTITY_TOTAL}%"
cd ..

# 1) Integration（backend 起動前提）
echo ""
echo "[2] Integration テスト"
if grep -r "//go:build integration" backend --include="*_test.go" -l 2>/dev/null | grep -q .; then
  cd backend
  BASE_URL="$BASE_URL" go test ./tests/integration/... -tags=integration -count=1 -v 2>&1 | tee tests/evidence/integration/integration.log || true
  cd ..
else
  echo "  (integration タグのテストなし - スキップ)"
fi

# 2) OIDC 整合チェック
echo ""
echo "[3] OIDC 整合チェック"
./backend/scripts/verify_oidc.sh "$BASE_URL" 2>&1 | tee $EVIDENCE/config/oidc_verify.log

# 3) 失敗系チェック
echo ""
echo "[4] 失敗系チェック"
./backend/scripts/verify_failure_cases.sh "$BASE_URL" 2>&1 | tee $EVIDENCE/security/failure_cases.log

# 4) Security（JWT改竄・PKCE・CSRF）
echo ""
echo "[5] Security テスト"
# JWT 改竄
TAMPERED="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0YW1wZXJlZCJ9.xxx"
curl -s -w "\n%{http_code}" "$BASE_URL/userinfo" -H "Authorization: Bearer $TAMPERED" \
  > $EVIDENCE/security/jwt_tamper.txt 2>&1
echo "  JWT改竄 → userinfo 拒否: $(tail -1 $EVIDENCE/security/jwt_tamper.txt)"

# 5) k6 負荷（k6 または docker で実行）
echo ""
echo "[6] k6 負荷テスト"
mkdir -p backend/tests/evidence/load
if command -v k6 &>/dev/null; then
  K6_BASE_URL="$BASE_URL" k6 run --summary-export=backend/tests/evidence/load/summary.json k6/token_flow.js 2>&1 | tee backend/tests/evidence/load/k6.log || true
elif command -v docker &>/dev/null; then
  K6_URL="$BASE_URL"
  [[ "$BASE_URL" = *localhost* ]] && K6_URL="${BASE_URL/localhost/host.docker.internal}"
  docker run --rm -v "$(pwd)/k6:/scripts" -v "$(pwd)/backend/tests/evidence/load:/out" -e K6_BASE_URL="$K6_URL" grafana/k6:latest run --summary-export=/out/summary.json /scripts/token_flow.js 2>&1 | tee backend/tests/evidence/load/k6.log || true
else
  echo "  (k6 / docker 未インストール - スキップ)"
fi

# 6) E2E Playwright（オプション：frontend で playwright が入っていれば）
echo ""
echo "[7] E2E Playwright"
if [ -f frontend/package.json ] && grep -q playwright frontend/package.json 2>/dev/null; then
  cd frontend
  # 既存の npm run dev を利用（5173 競合回避）
  npx playwright install --with-deps 2>/dev/null || true
  PLAYWRIGHT_SKIP_WEB_SERVER=1 VITE_API_BASE="$BASE_URL" npx playwright test 2>&1 | tee ../backend/tests/evidence/e2e/playwright.log || true
  cd ..
  # E2E で取得した id_token があれば iss/kid 自動検証
  if [ -f backend/tests/evidence/config/e2e_id_token.txt ]; then
    echo ""
    echo "[3b] ID Token iss/kid 整合チェック"
    ./backend/scripts/verify_id_token.sh "$BASE_URL" "$(cat backend/tests/evidence/config/e2e_id_token.txt)" 2>&1 | tee -a $EVIDENCE/config/oidc_verify.log || true
  fi
else
  echo "  (Playwright 未設定 - スキップ)"
fi

echo ""
echo "=== 証跡保存先: $EVIDENCE/ ==="
echo "  unit/       : coverage.out, coverage_core.out, coverage_entity.out, unit.log"
echo "  integration/: integration.log"
echo "  config/     : oidc_verify.log"
echo "  security/   : failure_cases.log, jwt_tamper.txt"
echo "  load/       : k6.log, summary.json"
echo "  e2e/        : playwright.log"
