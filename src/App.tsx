import { AuthProvider, useAuth } from "./context/AuthContext";
import { LoginScreen }   from "./screens/LoginScreen";
import { SetupScreen }   from "./screens/SetupScreen";
import { AccountScreen } from "./screens/AccountScreen";

function AppInner() {
  const { currentScreen } = useAuth();

  if (currentScreen === "loading") {
    return (
      <div className="screen">
        <div style={{ color: "var(--muted)", fontSize: 13 }}>Loading...</div>
      </div>
    );
  }
  if (currentScreen === "setup")   return <SetupScreen />;
  if (currentScreen === "login")   return <LoginScreen />;
  return <AccountScreen />;
}

export function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}
