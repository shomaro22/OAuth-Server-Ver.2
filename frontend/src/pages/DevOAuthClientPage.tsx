/**
 * 開発専用テストクライアント
 * /dev 配下。提出時は残してもOK。本番用途ではない。
 */
import { useState } from "react";
import { apiBase } from "../lib/api";

const TOKEN_ENDPOINT = `${apiBase}/oauth/token`;
const USERINFO_ENDPOINT = `${apiBase}/userinfo`;
const AUTH_ENDPOINT = `${apiBase}/oauth/authorize`;

const CLIENT_ID = "11111111-1111-1111-1111-111111111111";
const REDIRECT_URI = `${typeof window !== "undefined" ? window.location.origin : "http://localhost:5173"}/callback`;
const SCOPE = "openid profile";
const STATE_KEY = "dev_oauth_state";
const VERIFIER_KEY = "dev_pkce_verifier";
const NONCE_KEY = "dev_pkce_nonce";

function base64UrlEncode(bytes: ArrayBuffer): string {
  const uint8 = new Uint8Array(bytes);
  let binary = "";
  for (const b of uint8) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(str: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
}

function randomString(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer);
}

async function createPkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomString(32);
  const digest = await sha256(verifier);
  const challenge = base64UrlEncode(digest);
  return { verifier, challenge };
}

function buildAuthorizeUrl(codeChallenge: string, state: string, nonce: string): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    nonce,
  });
  return `${AUTH_ENDPOINT}?${params.toString()}`;
}

async function exchangeToken(code: string, verifier: string): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code,
    code_verifier: verifier,
  });

  const res = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    credentials: "include",
  });

  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new Error(`token exchange failed: ${res.status} ${JSON.stringify(json)}`);
  }
  return json;
}

function getCallbackParamsFromUrl(): { code: string; state: string } {
  const qp = new URLSearchParams(window.location.search);
  return { code: qp.get("code") ?? "", state: qp.get("state") ?? "" };
}

export default function DevOAuthClientPage() {
  const [code, setCode] = useState(() => getCallbackParamsFromUrl().code);
  const [state, setState] = useState(() => getCallbackParamsFromUrl().state);
  const [token, setToken] = useState<Record<string, unknown> | null>(null);
  const [userinfo, setUserinfo] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  const onLogin = async () => {
    setError("");
    setToken(null);
    setUserinfo(null);

    const newState = randomString(16);
    sessionStorage.setItem(STATE_KEY, newState);

    const { verifier, challenge } = await createPkcePair();
    sessionStorage.setItem(VERIFIER_KEY, verifier);

    const nonce = randomString(16);
    sessionStorage.setItem(NONCE_KEY, nonce);
    const url = buildAuthorizeUrl(challenge, newState, nonce);
    window.location.assign(url);
  };

  const onExchange = async () => {
    setError("");
    setToken(null);
    setUserinfo(null);

    const qp = new URLSearchParams(window.location.search);
    const c = qp.get("code") || code;
    const s = qp.get("state") || state;

    if (!c) {
      setError("code がありません。まず Login with OAuth を押してください。");
      return;
    }

    const expectedState = sessionStorage.getItem(STATE_KEY);
    if (expectedState) {
      if (!s) {
        setError("state が空です。CSRF の可能性があるため拒否します。");
        return;
      }
      if (expectedState !== s) {
        setError(`state mismatch. expected=${expectedState} actual=${s}`);
        return;
      }
    }

    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    if (!verifier) {
      setError("code_verifier が見つかりません（sessionStorage）。もう一度ログイン開始してください。");
      return;
    }

    try {
      const t = await exchangeToken(c, verifier);
      setToken(t);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const onUserInfo = async () => {
    setError("");
    setUserinfo(null);

    const at = token?.access_token as string | undefined;
    if (!at) {
      setError("access_token がありません。先に token exchange をしてください。");
      return;
    }
    try {
      const res = await fetch(USERINFO_ENDPOINT, {
        method: "GET",
        headers: { Authorization: `Bearer ${at}` },
        credentials: "include",
      });

      const text = await res.text();
      if (!res.ok) {
        setError(`userinfo failed: ${res.status} ${text}`);
        return;
      }

      setUserinfo(JSON.parse(text) as Record<string, unknown>);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const onClear = () => {
    setError("");
    setCode("");
    setState("");
    setToken(null);
    setUserinfo(null);
    sessionStorage.removeItem(STATE_KEY);
    sessionStorage.removeItem(VERIFIER_KEY);
    sessionStorage.removeItem(NONCE_KEY);
    const url = new URL(window.location.href);
    url.search = "";
    window.history.replaceState({}, "", url.toString());
  };

  return (
    <div style={{ padding: 16, maxWidth: 900 }}>
      <h1>開発専用 OAuth テストクライアント</h1>
      <p style={{ opacity: 0.8, color: "#666" }}>
        PKCE S256 / code → token 交換 / userinfo。本番用途ではありません。
      </p>
      <p style={{ fontSize: 12, color: "#888" }}>
        ※ http://localhost では refresh token（__Host-rt）が Secure Cookie のため保存されません。refresh 検証は curl で確認してください。
      </p>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "12px 0" }}>
        <button onClick={onLogin}>Login with OAuth</button>
        <button onClick={onExchange}>Exchange code → token</button>
        <button onClick={onUserInfo}>Call /userinfo</button>
        <button onClick={onClear}>Clear</button>
      </div>

      {error && (
        <pre style={{ background: "#fee", color: "#c00", padding: 12, borderRadius: 8, whiteSpace: "pre-wrap" }}>
          {error}
        </pre>
      )}

      <h2>Callback params</h2>
      <pre style={{ background: "#f6f6f6", color: "#333", padding: 12, borderRadius: 8, whiteSpace: "pre-wrap" }}>
        {JSON.stringify(
          {
            url: window.location.href,
            code: code || "(none)",
            state: state || "(none)",
            stored_state: sessionStorage.getItem(STATE_KEY) ? "***" : null,
            has_verifier: Boolean(sessionStorage.getItem(VERIFIER_KEY)),
            nonce: sessionStorage.getItem(NONCE_KEY) ?? "(none)",
          },
          null,
          2
        )}
      </pre>

      <h2>Token response</h2>
      <pre style={{ background: "#f6f6f6", color: "#333", padding: 12, borderRadius: 8, whiteSpace: "pre-wrap" }}>
        {token ? JSON.stringify(token, null, 2) : "(none)"}
      </pre>

      <h2>UserInfo</h2>
      <pre style={{ background: "#f6f6f6", color: "#333", padding: 12, borderRadius: 8, whiteSpace: "pre-wrap" }}>
        {userinfo ? JSON.stringify(userinfo, null, 2) : "(none)"}
      </pre>
    </div>
  );
}
