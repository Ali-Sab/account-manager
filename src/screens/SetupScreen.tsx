import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useAuth } from "../context/AuthContext";

type Step = "secret" | "confirm" | "done";

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }
  return (
    <button className="btn btn-ghost btn-sm" onClick={copy}>
      {copied ? "Copied!" : label}
    </button>
  );
}

export function SetupScreen() {
  const { reboot } = useAuth();
  const [step, setStep]           = useState<Step>("secret");
  const [secret, setSecret]       = useState("");
  const [formatted, setFormatted] = useState("");
  const [qrUrl, setQrUrl]         = useState("");
  const [username, setUsername]   = useState("");
  const [email, setEmail]         = useState("");
  const [password, setPassword]   = useState("");
  const [password2, setPassword2] = useState("");
  const [totpCode, setTotpCode]   = useState("");
  const [recoveryCodes, setRecoveryCodes]   = useState<string[]>([]);
  const [emailPending, setEmailPending]     = useState(false);
  const [error, setError]         = useState("");
  const [loading, setLoading]     = useState(false);
  const submittingRef = useRef(false);

  useEffect(() => {
    api("GET", "/api/setup/secret", undefined, false).then(data => {
      if (data.secret) {
        setSecret(data.secret as string);
        setFormatted(data.formatted as string);
        setQrUrl(data.qrDataUrl as string);
      }
    });
  }, []);

  async function submitSetup(code = totpCode) {
    if (submittingRef.current) return;
    setError("");
    if (!username.trim()) return setError("Username required");
    if (password.length < 12) return setError("Password must be at least 12 characters");
    if (password !== password2) return setError("Passwords do not match");
    if (!code) return setError("Enter the 6-digit code from your authenticator app");
    submittingRef.current = true;
    setLoading(true);
    try {
      const data = await api("POST", "/api/setup", { username: username.trim(), email: email.trim(), password, totpCode: code }, false);
      if (data.error) return setError(data.error as string);
      setRecoveryCodes(data.recoveryCodes as string[]);
      setEmailPending(data.emailPending === true);
      setStep("done");
    } finally {
      submittingRef.current = false;
      setLoading(false);
    }
  }

  function handleTotpChange(val: string) {
    const digits = val.replace(/\D/g, "").slice(0, 6);
    setTotpCode(digits);
    if (digits.length === 6) setTimeout(() => submitSetup(digits), 0);
  }

  const stepIdx = step === "secret" ? 0 : step === "confirm" ? 1 : 2;

  if (step === "done") {
    const allCodes = recoveryCodes.join("\n");
    return (
      <div className="screen">
        <div className="screen-box">
          <div className="screen-tag">ACCOUNT MANAGER</div>
          <div className="screen-title">Save your recovery codes</div>
          <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 16 }}>
            Store these somewhere safe. Each code works once — if you lose your authenticator, they&apos;re your only way back in.
          </p>
          <div className="card" style={{ marginBottom: 8 }}>
            <div className="code-list">
              {recoveryCodes.map(code => (
                <div key={code} className="code-item">{code}</div>
              ))}
            </div>
            <div className="code-copy-row">
              <CopyButton text={allCodes} label="Copy all" />
            </div>
          </div>
          {emailPending && (
            <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 16 }}>
              Check your inbox — a verification link has been sent to confirm your email address.
            </p>
          )}
          <button className="btn btn-gold" style={{ marginTop: 16 }} onClick={reboot}>
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

        <div className="steps" aria-hidden="true">
          {[0, 1].map(i => (
            <div key={i} className={`step-dot${i <= stepIdx ? " active" : ""}`} />
          ))}
        </div>

        {step === "secret" && (
          <div>
            <p className="field-hint" style={{ marginBottom: 16 }}>
              Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.) before continuing.
            </p>
            {qrUrl
              ? <img src={qrUrl} alt="TOTP QR code" style={{ width: "100%", maxWidth: 200, display: "block", margin: "0 auto 12px" }} />
              : <div style={{ display: "flex", justifyContent: "center", margin: "24px 0" }}><div className="spinner" /></div>
            }
            {formatted && (
              <div style={{ marginBottom: 20 }}>
                <div className="field-hint" style={{ marginBottom: 6 }}>Or enter manually:</div>
                <div className="secret-box">{formatted}</div>
                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 4 }}>
                  <CopyButton text={secret} label="Copy key" />
                </div>
              </div>
            )}
            <button className="btn btn-gold" onClick={() => setStep("confirm")} disabled={!qrUrl}>
              I&apos;ve scanned it
            </button>
          </div>
        )}

        {step === "confirm" && (
          <div>
            {error && <div className="error-msg" role="alert">{error}</div>}
            <div className="field">
              <label htmlFor="setup-username">Username</label>
              <input id="setup-username" value={username} onChange={e => setUsername(e.target.value)} autoFocus autoComplete="username" />
            </div>
            <div className="field">
              <label htmlFor="setup-email">
                Email <span style={{ color: "var(--muted)", fontWeight: 400 }}>(optional — for password reset)</span>
              </label>
              <input id="setup-email" type="email" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" />
            </div>
            <div className="field">
              <label htmlFor="setup-password">Password</label>
              <input id="setup-password" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" />
              <div className="field-hint">At least 12 characters.</div>
            </div>
            <div className="field">
              <label htmlFor="setup-password2">Confirm Password</label>
              <input id="setup-password2" type="password" value={password2} onChange={e => setPassword2(e.target.value)} autoComplete="new-password" />
            </div>
            <div className="field">
              <label htmlFor="setup-totp">Authenticator Code</label>
              <input id="setup-totp" value={totpCode} onChange={e => handleTotpChange(e.target.value)}
                placeholder="6 digits" maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
              <div className="field-hint">Enter the code shown in your authenticator app to confirm setup.</div>
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={() => submitSetup()} disabled={loading}>
                {loading ? "Setting up…" : "Complete Setup"}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => setStep("secret")}>Back</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
