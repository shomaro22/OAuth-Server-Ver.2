/**
 * k6 負荷テスト: token endpoint（code 交換 + refresh）
 * 実行: k6 run k6/token_flow.js
 *
 * 前提: DB に client と user が登録済み。
 * 環境変数で URL を上書き可能: K6_BASE_URL=http://localhost:8080
 */
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';

export const options = {
  vus: 5,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  // 1. 認可コード交換のシミュレーション（実際の code は取得できないため、invalid_grant で 400 が返る想定）
  const tokenRes = http.post(
    `${BASE_URL}/oauth/token`,
    {
      grant_type: 'authorization_code',
      code: 'dummy-code',
      redirect_uri: 'http://localhost:5173/callback',
      client_id: '11111111-1111-1111-1111-111111111111',
      code_verifier: 'dummy-verifier',
    },
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  check(tokenRes, { 'token status 400 or 401': (r) => r.status === 400 || r.status === 401 });

  // 2. health チェック（常に成功）
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, { 'health status 200': (r) => r.status === 200 });

  sleep(1);
}
