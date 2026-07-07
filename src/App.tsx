import { AuthProvider, useAuth } from "./context/AuthContext";
import { LoginScreen }          from "./screens/LoginScreen";
import { SetupScreen }          from "./screens/SetupScreen";
import { AccountScreen }        from "./screens/AccountScreen";
import { InviteScreen }         from "./screens/InviteScreen";
import { ResetPasswordScreen }  from "./screens/ResetPasswordScreen";
import { EmailVerifyScreen }    from "./screens/EmailVerifyScreen";

function AppInner() {
  const { currentScreen, setScreen } = useAuth();

  // Check for invite token in URL on initial render.
  const params = new URLSearchParams(window.location.search);
  const inviteToken = params.get("invite");

  const verifyEmailToken = params.get("verify-email");
  if (verifyEmailToken) {
    return (
      <EmailVerifyScreen
        token={verifyEmailToken}
        onDone={() => {
          window.history.replaceState({}, "", window.location.pathname);
          setScreen("account");
        }}
      />
    );
  }

  const resetToken = params.get("reset");
  if (resetToken) {
    return (
      <ResetPasswordScreen
        token={resetToken}
        onDone={() => window.location.replace(window.location.pathname)}
      />
    );
  }

  if (inviteToken) {
    return (
      <InviteScreen
        token={inviteToken}
        onDone={() => window.location.replace(window.location.pathname)}
      />
    );
  }

  if (currentScreen === "loading") {
    return (
      <div className="spinner-screen">
        <div className="spinner" />
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
