import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    // login_challenge 等を保持して /login へ
    return <Navigate to={`/login${location.search}`} replace />;
  }
  return <>{children}</>;
}
