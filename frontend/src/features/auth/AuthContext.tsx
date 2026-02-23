/* eslint-disable react-refresh/only-export-components -- useAuth is a hook, not a component */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

const AUTH_KEY = "auth";

type AuthState = {
  isAuthenticated: boolean;
  setAuthenticated: (v: boolean) => void;
};

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setAuthenticatedState] = useState(
    () => !!sessionStorage.getItem(AUTH_KEY)
  );

  const setAuthenticated = useCallback((v: boolean) => {
    if (v) {
      sessionStorage.setItem(AUTH_KEY, "1");
    } else {
      sessionStorage.removeItem(AUTH_KEY);
    }
    setAuthenticatedState(v);
  }, []);

  const value = useMemo(
    () => ({ isAuthenticated, setAuthenticated }),
    [isAuthenticated, setAuthenticated]
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("AuthProvider is missing");
  return v;
}
