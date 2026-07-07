import { useEffect, useState, useRef } from "react";
import { api, fetchCsrfToken } from "../api";
import { useAuth } from "../context/AuthContext";

type Step = "passkey" | "password-step1" | "password-step2" | "recovery" | "forgot" | "forgot-sent";

function b64url(buf: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function fromB64url(s: string): Uint8Array {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b), c => c.charCodeAt(0));
}

const STEP_ORDER: Step[] = ["passkey", "password-step1", "password-step2"];

function StepDots({ current }: { current: Step }) {
  const idx = STEP_ORDER.indexOf(current);
  if (idx < 0) return null;
  return (
    <div className="steps" aria-hidden="true">
      {STEP_ORDER.map((s, i) => (
        <div key={s} className={`step-dot${i <= idx ? " active" : ""}`} />
      ))}
    </div>
  );
}

export function LoginScreen() {
  const { loginHasPasskeys, login } = useAuth();
  const [step, setStep]         = useState<Step>(loginHasPasskeys ? "passkey" : "password-step1");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recovery, setRecovery] = useState("");
  const [forgotEmail, setForgotEmail] = useState("");
  const [sentEmail, setSentEmail]     = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (step === "password-step2") setTimeout(() => totpRef.current?.focus(), 50);
  }, [step]);

  function goTo(s: Step) { setStep(s); setError(""); }

  async function loginWithPasskey() {
    setError(""); setLoading(true);
    try {
      const opts = await api("POST", "/api/webauthn/login/start", {}, false);
      if (opts.error) { setError(opts.error as string); return; }

      const pk = (opts as unknown as { publicKey: Record<string, unknown> }).publicKey;
      const publicKey = {
        ...(pk as object),
        challenge:        fromB64url(pk.challenge as string),
        allowCredentials: ((pk.allowCredentials as {id: string; type: string}[]) || []).map(c => ({
          type: c.type as PublicKeyCredentialType,
          id: fromB64url(c.id),
        })),
      } as unknown as PublicKeyCredentialRequestOptions;

      const assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential;
      const resp      = assertion.response as AuthenticatorAssertionResponse;
      const encoded = {
        id:    assertion.id,
        rawId: b64url(assertion.rawId),
        type:  assertion.type,
        response: {
          clientDataJSON:    b64url(resp.clientDataJSON),
          authenticatorData: b64url(resp.authenticatorData),
          signature:         b64url(resp.signature),
          userHandle:        resp.userHandle ? b64url(resp.userHandle) : undefined,
        },
      };

      const result = await api("POST", "/api/webauthn/login/finish", encoded, false);
      if (result.error) { setError(result.error as string); return; }
      await fetchCsrfToken();
      login(result.accessToken as string);
    } catch (e: unknown) {
      const err = e as { name?: string };
      if (err.name === "NotAllowedError") setError("Passkey sign-in was cancelled");
      else setError("Passkey sign-in failed");
    } finally {
      setLoading(false);
    }
  }

  async function submitStep1() {
    setError(""); setLoading(true);
    const data = await api("POST", "/api/auth/login", { username: username.trim(), password }, false);
    setLoading(false);
    if (data.error) return setError(data.error as string);
    setMfaToken(data.mfaToken as string);
    setStep("password-step2");
  }

  async function submitStep2(code = totpCode) {
    setError(""); setLoading(true);
    const data = await api("POST", "/api/auth/mfa", { mfaToken, code }, false);
    setLoading(false);
    if (data.error) return setError(data.error as string);
    login(data.accessToken as string, data.csrfToken as string | undefined);
  }

  async function submitForgotPassword() {
    setError(""); setLoading(true);
    await api("POST", "/api/auth/forgot-password", { email: forgotEmail.trim() }, false);
    setLoading(false);
    setSentEmail(forgotEmail.trim());
    setStep("forgot-sent");
  }

  async function submitRecovery() {
    setError(""); setLoading(true);
    const data = await api("POST", "/api/auth/recovery", { mfaToken, code: recovery }, false);
    setLoading(false);
    if (data.error) return setError(data.error as string);
    login(data.accessToken as string, data.csrfToken as string | undefined);
  }

  function handleTotpChange(val: string) {
    const digits = val.replace(/\D/g, "").slice(0, 6);
    setTotpCode(digits);
    if (digits.length === 6) setTimeout(() => submitStep2(digits), 0);
  }

  return (
    <div className="screen">
      <div className="screen-box">
        <div className="screen-tag">ACCOUNT MANAGER</div>
        <div className="screen-title">Sign in</div>

        <div aria-live="polite" aria-atomic="true">
          {error && <div className="error-msg" role="alert">{error}</div>}
        </div>

        {step === "passkey" && (
          <div>
            <StepDots current="passkey" />
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20 }}>
              Use a passkey saved on this device or a hardware security key.
            </p>
            <button className="btn btn-gold" style={{ width: "100%", marginBottom: 10 }}
              onClick={loginWithPasskey} disabled={loading}>
              {loading ? <span className="spinner" style={{ width: 16, height: 16, borderWidth: 1.5 }} /> : "Sign in with Passkey"}
            </button>
            <div style={{ textAlign: "center" }}>
              <button className="btn btn-ghost btn-sm" onClick={() => goTo("password-step1")}>
                Use password instead
              </button>
            </div>
          </div>
        )}

        {step === "password-step1" && (
          <div>
            <StepDots current="password-step1" />
            {loginHasPasskeys && (
              <div style={{ marginBottom: 10, textAlign: "right" }}>
                <button className="btn btn-ghost btn-sm" onClick={() => goTo("passkey")}>
                  Use passkey instead
                </button>
              </div>
            )}
            <div className="field">
              <label htmlFor="login-username">Username</label>
              <input id="login-username" value={username} onChange={e => setUsername(e.target.value)} autoFocus
                autoComplete="username"
                onKeyDown={e => { if (e.key === "Enter") submitStep1(); }} />
            </div>
            <div className="field">
              <label htmlFor="login-password">Password</label>
              <input id="login-password" type="password" value={password} onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                onKeyDown={e => { if (e.key === "Enter") submitStep1(); }} />
            </div>
            <button className="btn btn-gold" onClick={submitStep1} disabled={loading}>
              {loading ? "Checking…" : "Continue"}
            </button>
            <div style={{ marginTop: 12, textAlign: "center" }}>
              <button className="btn btn-ghost btn-sm" onClick={() => goTo("forgot")}>
                Forgot password?
              </button>
            </div>
          </div>
        )}

        {step === "password-step2" && (
          <div>
            <StepDots current="password-step2" />
            <div className="field">
              <label htmlFor="login-totp">Authenticator Code</label>
              <input id="login-totp" ref={totpRef} value={totpCode}
                onChange={e => handleTotpChange(e.target.value)}
                placeholder="6 digits" maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
              <div className="field-hint">Enter the 6-digit code from your authenticator app.</div>
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={() => submitStep2()} disabled={loading || totpCode.length < 6}>
                {loading ? "Verifying…" : "Verify"}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => goTo("recovery")}>
                Use recovery code
              </button>
            </div>
          </div>
        )}

        {step === "forgot" && (
          <div>
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 16 }}>
              Enter your email address and we&apos;ll send you a reset link.
            </p>
            <div className="field">
              <label htmlFor="forgot-email">Email</label>
              <input id="forgot-email" type="email" value={forgotEmail}
                onChange={e => setForgotEmail(e.target.value)}
                autoFocus autoComplete="email"
                onKeyDown={e => { if (e.key === "Enter" && forgotEmail.trim()) submitForgotPassword(); }} />
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={submitForgotPassword}
                disabled={loading || !forgotEmail.trim()}>
                {loading ? "Sending…" : "Send Reset Link"}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => goTo("password-step1")}>Back</button>
            </div>
          </div>
        )}

        {step === "forgot-sent" && (
          <div>
            <div className="success-msg" style={{ marginBottom: 16 }}>Reset link sent.</div>
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 8 }}>
              If <strong>{sentEmail}</strong> is registered, you&apos;ll receive an email shortly.
            </p>
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20 }}>
              Check your spam folder if it doesn&apos;t arrive within a few minutes.
            </p>
            <button className="btn btn-ghost btn-sm" onClick={() => goTo("password-step1")}>
              Back to sign in
            </button>
          </div>
        )}

        {step === "recovery" && (
          <div>
            <div className="field">
              <label htmlFor="login-recovery">Recovery Code</label>
              <input id="login-recovery" value={recovery} onChange={e => setRecovery(e.target.value)}
                placeholder="xxxx-xxxx-xx" autoFocus
                onKeyDown={e => { if (e.key === "Enter") submitRecovery(); }} />
              <div className="field-hint">Each code works once. Use one of the codes you saved when you first set up your account.</div>
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={submitRecovery} disabled={loading || !recovery.trim()}>
                {loading ? "Checking…" : "Sign in"}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => goTo("password-step2")}>
                Back to TOTP
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
