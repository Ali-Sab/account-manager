import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, fetchCsrfToken, setAccessToken, setCsrfToken } from "../api";

type Screen = "loading" | "setup" | "login" | "account";

interface AuthContextValue {
  currentScreen: Screen;
  loginHasPasskeys: boolean;
  login: (accessToken: string, csrfToken?: string) => void;
  logout: () => Promise<void>;
  setScreen: (s: Screen) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [currentScreen, setCurrentScreen] = useState<Screen>("loading");
  const [loginHasPasskeys, setLoginHasPasskeys] = useState(false);

  useEffect(() => { boot(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function boot() {
    try {
      const status = await api("GET", "/api/setup/status", undefined, false);
      if (!status.configured) { setCurrentScreen("setup"); return; }

      setLoginHasPasskeys(!!status.hasPasskeys);
      await fetchCsrfToken();

      const data = await api("POST", "/api/auth/refresh", undefined, false);
      if (typeof data.accessToken === "string") {
        setAccessToken(data.accessToken);
        setCurrentScreen("account");
      } else {
        setCurrentScreen("login");
      }
    } catch {
      setCurrentScreen("login");
    }
  }

  function login(accessToken: string, csrfToken?: string) {
    setAccessToken(accessToken);
    if (csrfToken) setCsrfToken(csrfToken);
    setCurrentScreen("account");
  }

  async function logout() {
    await api("POST", "/api/auth/logout").catch(() => {});
    setAccessToken(null);
    setCsrfToken(null);
    setCurrentScreen("login");
  }

  return (
    <AuthContext.Provider value={{ currentScreen, loginHasPasskeys, login, logout, setScreen: setCurrentScreen }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
