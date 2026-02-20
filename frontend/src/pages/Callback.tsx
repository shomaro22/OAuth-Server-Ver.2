import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * OAuth 認可後のコールバックページ。
 * redirect_uri に code と state が返ってくるので、E2E で code を控えやすく表示する。
 */
export default function Callback() {
  const [searchParams] = useSearchParams();
  const code = searchParams.get("code") ?? "";
  const state = searchParams.get("state") ?? "";
  const error = searchParams.get("error") ?? "";

  const hasCode = useMemo(() => code.length > 0, [code]);

  return (
    <div style={{ maxWidth: 560, margin: "40px auto", padding: 24 }}>
      <h1>OAuth Callback</h1>

      {error ? (
        <p style={{ color: "#c00" }}>
          error: {error}
          {searchParams.get("error_description") && (
            <> — {searchParams.get("error_description")}</>
          )}
        </p>
      ) : hasCode ? (
        <>
          <p style={{ color: "#0a0" }}>✅ 認可成功。code を控えて /oauth/token で交換してください。</p>
          <div style={{ marginTop: 16, padding: 12, background: "#f5f5f5", borderRadius: 8 }}>
            <div style={{ marginBottom: 8 }}>
              <strong>code:</strong>
              <br />
              <code style={{ wordBreak: "break-all" }}>{code}</code>
            </div>
            {state && (
              <div>
                <strong>state:</strong> <code>{state}</code>
              </div>
            )}
          </div>
          <p style={{ marginTop: 16, fontSize: 12 }}>
            gen_pkce.js が出力した curl の <code>code=</code> に上記を貼り付けて実行。
          </p>
        </>
      ) : (
        <p>
          code がありません。/oauth/authorize からログインフローを開始してください。
        </p>
      )}
    </div>
  );
}
