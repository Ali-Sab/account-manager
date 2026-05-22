import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../context/AuthContext";

type Step = "secret" | "confirm" | "done";

export function SetupScreen() {
  const { setScreen } = useAuth();
  const [step, setStep]         = useState<Step>("secret");
  const [secret, setSecret]     = useState("");
  const [formatted, setFormatted] = useState("");
  const [qrUrl, setQrUrl]       = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  useEffect(() => {
    api("GET", "/api/setup/secret", undefined, false).then(data => {
      if (data.secret) {
        setSecret(data.secret as string);
        setFormatted(data.formatted as string);
        setQrUrl(data.qrDataUrl as string);
      }
    });
  }, []);

  async function submitSetup() {
    setError("");
    if (!username.trim()) return setError("Username required");
    if (password.length < 6) return setError("Password must be at least 6 characters");
    if (password !== password2) return setError("Passwords do not match");
    if (!totpCode) return setError("Enter the 6-digit code from your authenticator app");
    setLoading(true);
    const data = await api("POST", "/api/setup", { username: username.trim(), password, totpCode }, false);
    setLoading(false);
    if (data.error) return setError(data.error as string);
    setRecoveryCodes(data.recoveryCodes as string[]);
    setStep("done");
  }

  if (step === "done") {
    return (
      <div className="screen">
        <div className="screen-box">
          <div className="screen-tag">ACCOUNT MANAGER</div>
          <div className="screen-title">Save your recovery codes</div>
          <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 16 }}>
            Store these somewhere safe. Each code can only be used once if you lose access to your authenticator.
          </p>
          <div className="card" style={{ marginBottom: 20 }}>
            {recoveryCodes.map(code => (
              <div key={code} style={{ fontFamily: "monospace", fontSize: 14, padding: "3px 0" }}>{code}</div>
            ))}
          </div>
          <button className="btn btn-gold" onClick={() => setScreen("login")}>
            Continue to Sign In
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="screen-box">
        <div className="screen-tag">ACCOUNT MANAGER</div>
        <div className="screen-title">Set up your account</div>

        {step === "secret" && (
          <div>
            <p className="field-hint" style={{ marginBottom: 16 }}>
              Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.) before continuing.
            </p>
            {qrUrl && <img src={qrUrl} alt="TOTP QR code" style={{ width: "100%", maxWidth: 200, display: "block", margin: "0 auto 12px" }} />}
            <div className="field-hint" style={{ marginBottom: 20 }}>
              Or enter manually: <span className="secret-box" style={{ display: "inline", fontSize: 13, letterSpacing: "0.1em", padding: "2px 6px" }}>{formatted}</span>
            </div>
            <button className="btn btn-gold" onClick={() => setStep("confirm")}>
              I&apos;ve scanned it
            </button>
          </div>
        )}

        {step === "confirm" && (
          <div>
            {error && <div className="error-msg">{error}</div>}
            <div className="field">
              <label>Username</label>
              <input value={username} onChange={e => setUsername(e.target.value)} autoFocus />
            </div>
            <div className="field">
              <label>Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
            </div>
            <div className="field">
              <label>Confirm Password</label>
              <input type="password" value={password2} onChange={e => setPassword2(e.target.value)} />
            </div>
            <div className="field">
              <label>Authenticator Code</label>
              <input value={totpCode} onChange={e => setTotpCode(e.target.value)}
                placeholder="6-digit code" maxLength={6}
                onKeyDown={e => { if (e.key === "Enter") submitSetup(); }} />
              <div className="field-hint">Enter the code shown in your authenticator app to confirm setup.</div>
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={submitSetup} disabled={loading}>Complete Setup</button>
              <button className="btn btn-ghost btn-sm" onClick={() => setStep("secret")}>Back</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
