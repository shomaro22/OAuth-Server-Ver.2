import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { apiFetch } from "../lib/api";
import type { ApiError } from "../lib/api";
import type { LoginResponse } from "../types/oidc";
import { useAuth } from "../features/auth/AuthContext";

export default function Login() {
  const [searchParams] = useSearchParams();
  const loginChallenge = useMemo(
    () => searchParams.get("login_challenge") ?? "",
    [searchParams]
  );
  const { setAuthenticated } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string>("");

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");

    if (!loginChallenge) {
      setErr(
        "login_challenge がありません。/oauth/authorize から来てください。"
      );
      return;
    }

    try {
      const data = await apiFetch<LoginResponse>("/sessions/login", {
        method: "POST",
        body: JSON.stringify({
          login_challenge: loginChallenge,
          username,
          password,
        }),
      });

      setAuthenticated(true);
      // next_url は絶対URL（SERVER_BASE_URL + path）なのでそのまま遷移
      window.location.href = data.next_url;
    } catch (e) {
      const apiErr = e as ApiError;
      setErr(`ログイン失敗: ${apiErr.status} ${apiErr.message}`);
    }
  };

  return (
    <div style={{ maxWidth: 420, margin: "40px auto" }}>
      <h1>Login</h1>

      <form onSubmit={onSubmit}>
        <div>
          <label>Username</label>
          <br />
          <input
            data-testid="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div style={{ marginTop: 12 }}>
          <label>Password</label>
          <br />
          <input
            data-testid="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {err && (
          <p data-testid="login-error" style={{ marginTop: 12 }}>
            {err}
          </p>
        )}

        <button
          data-testid="login-submit"
          style={{ marginTop: 16 }}
          type="submit"
        >
          Login
        </button>
      </form>

      <p style={{ marginTop: 20, fontSize: 12 }}>
        login_challenge: {loginChallenge || "(none)"}
      </p>
    </div>
  );
}
