import { useEffect, useState, useRef } from "react";
import { api, fetchCsrfToken } from "../api";
import { useAuth } from "../context/AuthContext";

type Step = "passkey" | "password-step1" | "password-step2" | "recovery";

// Minimal passkey codec (same as gamebacklog)
function b64url(buf: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function fromB64url(s: string): Uint8Array {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b), c => c.charCodeAt(0));
}

export function LoginScreen() {
  const { loginHasPasskeys, login } = useAuth();
  const [step, setStep]         = useState<Step>(loginHasPasskeys ? "passkey" : "password-step1");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recovery, setRecovery] = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (step === "password-step2") setTimeout(() => totpRef.current?.focus(), 50);
  }, [step]);

  async function loginWithPasskey() {
    setError("");
    if (!window.PublicKeyCredential) return setError("Browser does not support passkeys");
    setLoading(true);
    try {
      const opts = await api("POST", "/api/webauthn/login/start", {}, false);
      if (opts.error) { setError(opts.error as string); setLoading(false); return; }

      // Decode challenge and allowCredentials
      const publicKey = {
        ...(opts as object),
        challenge:         fromB64url(opts.challenge as string),
        allowCredentials: ((opts.allowCredentials as {id: string}[]) || []).map(c => ({
          ...c, id: fromB64url(c.id),
        })),
      } as PublicKeyCredentialRequestOptions;

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
      if (result.error) { setError(result.error as string); setLoading(false); return; }
      await fetchCsrfToken();
      login(result.accessToken as string);
    } catch (e: unknown) {
      const err = e as { name?: string };
      if (err.name === "NotAllowedError") setError("Passkey sign-in was cancelled");
      else setError("Passkey sign-in failed");
    }
    setLoading(false);
  }

  async function submitStep1() {
    setError("");
    const data = await api("POST", "/api/auth/login", { username: username.trim(), password }, false);
    if (data.error) return setError(data.error as string);
    setMfaToken(data.mfaToken as string);
    setStep("password-step2");
  }

  async function submitStep2() {
    setError("");
    const data = await api("POST", "/api/auth/mfa", { mfaToken, code: totpCode }, false);
    if (data.error) return setError(data.error as string);
    login(data.accessToken as string, data.csrfToken as string | undefined);
  }

  async function submitRecovery() {
    setError("");
    const data = await api("POST", "/api/auth/recovery", { mfaToken, code: recovery }, false);
    if (data.error) return setError(data.error as string);
    login(data.accessToken as string, data.csrfToken as string | undefined);
  }

  return (
    <div className="screen">
      <div className="screen-box">
        <div className="screen-tag">ACCOUNT MANAGER</div>
        <div className="screen-title">Sign in</div>

        {step === "passkey" && (
          <div>
            {error && <div className="error-msg">{error}</div>}
            <button className="btn btn-gold" style={{ width: "100%", marginBottom: 10 }} onClick={loginWithPasskey} disabled={loading}>
              Sign in with Passkey
            </button>
            <div style={{ textAlign: "center" }}>
              <button className="btn btn-ghost btn-sm" onClick={() => { setStep("password-step1"); setError(""); }}>
                Use password instead
              </button>
            </div>
          </div>
        )}

        {step === "password-step1" && (
          <div>
            {loginHasPasskeys && (
              <div style={{ marginBottom: 10, textAlign: "right" }}>
                <button className="btn btn-ghost btn-sm" onClick={() => { setStep("passkey"); setError(""); }}>
                  Use passkey instead
                </button>
              </div>
            )}
            {error && <div className="error-msg">{error}</div>}
            <div className="field">
              <label>Username</label>
              <input value={username} onChange={e => setUsername(e.target.value)} autoFocus
                onKeyDown={e => { if (e.key === "Enter") submitStep1(); }} />
            </div>
            <div className="field">
              <label>Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") submitStep1(); }} />
            </div>
            <button className="btn btn-gold" onClick={submitStep1}>Continue</button>
          </div>
        )}

        {step === "password-step2" && (
          <div>
            {error && <div className="error-msg">{error}</div>}
            <div className="field">
              <label>Authenticator Code</label>
              <input ref={totpRef} value={totpCode} onChange={e => setTotpCode(e.target.value)}
                placeholder="6-digit code" maxLength={6}
                onKeyDown={e => { if (e.key === "Enter") submitStep2(); }} />
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={submitStep2}>Verify</button>
              <button className="btn btn-ghost btn-sm" onClick={() => { setStep("recovery"); setError(""); }}>
                Use recovery code
              </button>
            </div>
          </div>
        )}

        {step === "recovery" && (
          <div>
            {error && <div className="error-msg">{error}</div>}
            <div className="field">
              <label>Recovery Code</label>
              <input value={recovery} onChange={e => setRecovery(e.target.value)}
                placeholder="xxxx-xxxx-xx"
                onKeyDown={e => { if (e.key === "Enter") submitRecovery(); }} />
            </div>
            <div className="btn-row">
              <button className="btn btn-gold" onClick={submitRecovery}>Sign in</button>
              <button className="btn btn-ghost btn-sm" onClick={() => { setStep("password-step2"); setError(""); }}>
                Back to TOTP
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
