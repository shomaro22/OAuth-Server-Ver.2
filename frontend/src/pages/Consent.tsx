import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { apiBase } from "../lib/api";

/**
 * OAuth 同意画面。prompt=consent 時に表示。
 * 許可 → /oauth/authorize/continue?login_challenge=...&approved=true
 * 拒否 → /oauth/authorize/deny?login_challenge=...
 */
export default function Consent() {
  const [searchParams] = useSearchParams();
  const loginChallenge = searchParams.get("login_challenge") ?? "";
  const scope = searchParams.get("scope") ?? "openid";
  const scopes = useMemo(() => scope.split(/\s+/).filter(Boolean), [scope]);

  const onApprove = () => {
    window.location.href = `${apiBase}/oauth/authorize/continue?login_challenge=${loginChallenge}&approved=true`;
  };

  const onDeny = () => {
    window.location.href = `${apiBase}/oauth/authorize/deny?login_challenge=${loginChallenge}`;
  };

  if (!loginChallenge) {
    return (
      <div style={{ maxWidth: 420, margin: "40px auto" }}>
        <p data-testid="consent-challenge-error">login_challenge がありません。</p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 420, margin: "40px auto" }}>
      <h1>アプリの許可</h1>
      <p>以下の権限へのアクセスを許可しますか？</p>
      <ul style={{ marginTop: 16 }}>
        {scopes.map((s) => (
          <li key={s}>{scopeLabel(s)}</li>
        ))}
      </ul>
      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <button data-testid="consent-approve" type="button" onClick={onApprove}>
          許可する
        </button>
        <button type="button" onClick={onDeny} style={{ background: "#ccc" }}>
          拒否する
        </button>
      </div>
    </div>
  );
}

function scopeLabel(s: string): string {
  const labels: Record<string, string> = {
    openid: "OpenID Connect（認証）",
    profile: "プロフィール情報",
    email: "メールアドレス",
  };
  return labels[s] ?? s;
}
