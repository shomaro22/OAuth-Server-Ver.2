import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Consent from "./pages/Consent";
import Callback from "./pages/Callback";
import DevOAuthClientPage from "./pages/DevOAuthClientPage";
import { RequireAuth } from "./features/auth/RequireAuth";

function Home() {
  return (
    <div style={{ maxWidth: 560, margin: "40px auto", padding: 24 }}>
      <h1>OAuth Server Frontend</h1>
      <p>authorize から開始してください。</p>
      <ul>
        <li>
          <a href="/login">/login</a>
        </li>
        <li>
          <a href="/consent">/consent</a>
        </li>
        <li>
          <a href="/callback">/callback</a>
        </li>
        <li>
          <a href="/dev/oauth-client">/dev/oauth-client（開発専用）</a>
        </li>
      </ul>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/consent"
          element={
            <RequireAuth>
              <Consent />
            </RequireAuth>
          }
        />
        <Route path="/callback" element={<Callback />} />
        <Route path="/dev/oauth-client" element={<DevOAuthClientPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
