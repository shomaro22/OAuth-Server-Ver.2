import { useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8080";

export default function Login() {
  const params = new URLSearchParams(window.location.search);
  const loginChallenge = useMemo(() => params.get("login_challenge") ?? "", []);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string>("");

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");

    if (!loginChallenge) {
      setErr("login_challenge がありません。/oauth/authorize から来てください。");
      return;
    }

    const res = await fetch(`${API_BASE}/sessions/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include", // ★これが必須（Cookie受け取り）
      body: JSON.stringify({
        login_challenge: loginChallenge,
        username,
        password,
      }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      setErr(`ログイン失敗: ${res.status} ${text}`);
      return;
    }

    const data = (await res.json()) as { next_url: string };

    // next_url は絶対URL（SERVER_BASE_URL + path）なのでそのまま遷移
    window.location.href = data.next_url;
  };

  return (
    <div style={{ maxWidth: 420, margin: "40px auto" }}>
      <h1>Login</h1>

      <form onSubmit={onSubmit}>
        <div>
          <label>Username</label>
          <br />
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div style={{ marginTop: 12 }}>
          <label>Password</label>
          <br />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {err && <p style={{ marginTop: 12 }}>{err}</p>}

        <button style={{ marginTop: 16 }} type="submit">
          Login
        </button>
      </form>

      <p style={{ marginTop: 20, fontSize: 12 }}>
        login_challenge: {loginChallenge || "(none)"}
      </p>
    </div>
  );
}
