#!/bin/bash
# 提出用 zip 作成（node_modules / .env / .DS_Store / cookies.txt を除外）
# 実行: ./scripts/create_submission_zip.sh
# 出力: プロジェクトルートに submission.zip が作成される

set -e
cd "$(dirname "$0")/.."
OUT="submission.zip"

echo "=== 提出用 zip 作成 ==="
echo "除外: node_modules/, .env, .DS_Store, cookies.txt, frontend/dist/"
echo ""

# 既存の zip を削除
rm -f "$OUT"

# zip 作成（除外パターン指定）
zip -r "$OUT" . \
  -x "*.git*" \
  -x "*node_modules*" \
  -x "*/.env" \
  -x ".env" \
  -x "*/.DS_Store" \
  -x "*/.DS_Store" \
  -x "*.DS_Store" \
  -x "*cookies.txt" \
  -x "*frontend/dist*" \
  -x "*.zip" \
  -x "*__MACOSX*" \
  -x "*.env.local" \
  -x "*.env.*.local"

echo ""
echo "作成完了: $OUT"
ls -lh "$OUT"
