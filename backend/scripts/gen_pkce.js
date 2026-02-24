#!/usr/bin/env node
/**
 * PKCE code_verifier と code_challenge (S256) を生成する。
 * 使い方: node scripts/gen_pkce.js [redirect_uri]
 * 例: node scripts/gen_pkce.js http://localhost:5173/callback
 */
const crypto = require("crypto");

const redirectUri = process.argv[2] || "http://localhost:5173/callback";
const encodedRedirect = encodeURIComponent(redirectUri);

const verifier = crypto.randomBytes(32).toString("base64url");
const challenge = crypto
  .createHash("sha256")
  .update(verifier)
  .digest("base64url");

console.log("code_verifier:", verifier);
console.log("code_challenge:", challenge);
console.log("");
console.log("--- authorize URL（ブラウザで開く）---");
console.log(
  `http://localhost:8080/oauth/authorize?response_type=code&client_id=11111111-1111-1111-1111-111111111111&redirect_uri=${encodedRedirect}&scope=openid%20profile&state=abc&code_challenge=${challenge}&code_challenge_method=S256&nonce=test`,
);
console.log("");
console.log("--- /oauth/token 交換（code を控えた後に実行）---");
console.log(
  `curl -X POST http://localhost:8080/oauth/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=L_GjZXYCX276EwvSbEfu6meHYBxiiAQM6PPUxgvjn24" \\
  -d "redirect_uri=${redirectUri}" \\
  -d "client_id=11111111-1111-1111-1111-111111111111" \\
  -d "code_verifier=${verifier}" \\
  -c cookies.txt -b cookies.txt`,
);
