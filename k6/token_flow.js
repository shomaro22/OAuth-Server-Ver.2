/**
 * k6 負荷テスト: 200 成功する API（http_req_failed < 0.01 達成用）
 * 対象: /health, /.well-known/openid-configuration, /jwks
 *
 * 測定範囲: authorize/token は code 取得が必要なため本スクリプトでは対象外。
 * 提出時は「測定困難な理由・代替測定・今後の計画」を明記。
 *
 * 環境変数: K6_BASE_URL=http://localhost:8080
 */
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';

export const options = {
  vus: 5,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<300', 'p(99)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  // 1. /health → 200
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, { 'health 200': (r) => r.status === 200 });

  // 2. Discovery → 200
  const discRes = http.get(`${BASE_URL}/.well-known/openid-configuration`);
  check(discRes, { 'discovery 200': (r) => r.status === 200 });

  // 3. JWKS → 200
  const jwksRes = http.get(`${BASE_URL}/jwks`);
  check(jwksRes, { 'jwks 200': (r) => r.status === 200 });

  sleep(0.5);
}
