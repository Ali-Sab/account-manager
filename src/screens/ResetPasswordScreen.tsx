import { useState } from "react";
import { api } from "../api";

interface Props {
  token: string;
  onDone: () => void;
}

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

export function ResetPasswordScreen({ token, onDone }: Props) {
  const [newPassword, setNewPassword]   = useState("");
  const [newPassword2, setNewPassword2] = useState("");
  const [totpCode, setTotpCode]         = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError]               = useState("");
  const [loading, setLoading]           = useState(false);
  const [done, setDone]                 = useState(false);

  async function submit(code = totpCode) {
    setError("");
    if (newPassword.length < 12) return setError("Password must be at least 12 characters");
    if (newPassword !== newPassword2) return setError("Passwords do not match");
    if (!code) return setError("Enter the 6-digit code from your authenticator app");
    setLoading(true);
    const data = await api("POST", "/api/auth/reset-password", { token, newPassword, totpCode: code }, false);
    setLoading(false);
    if (data.error) return setError(data.error as string);
    setRecoveryCodes(data.recoveryCodes as string[]);
    setDone(true);
  }

  function handleTotpChange(val: string) {
    const digits = val.replace(/\D/g, "").slice(0, 6);
    setTotpCode(digits);
    if (digits.length === 6) submit(digits);
  }

  if (done && recoveryCodes.length > 0) {
    return (
      <div className="screen">
        <div className="screen-box">
          <div className="screen-tag">ACCOUNT MANAGER</div>
          <div className="screen-title">Save your new recovery codes</div>
          <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 16 }}>
            Your password has been reset. Your old recovery codes are no longer valid — store these new ones somewhere safe.
          </p>
          <div className="card" style={{ marginBottom: 8 }}>
            <div className="code-list">
              {recoveryCodes.map(c => <div key={c} className="code-item">{c}</div>)}
            </div>
            <div className="code-copy-row">
              <CopyButton text={recoveryCodes.join("\n")} label="Copy all" />
            </div>
          </div>
          <button className="btn btn-gold" style={{ marginTop: 16 }} onClick={onDone}>Continue</button>
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="screen-box">
        <div className="screen-tag">ACCOUNT MANAGER</div>
        <div className="screen-title">Reset your password</div>
        {error && <div className="error-msg" role="alert">{error}</div>}
        <div className="field">
          <label htmlFor="reset-pw">New Password</label>
          <input id="reset-pw" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)}
            autoFocus autoComplete="new-password" />
          <div className="field-hint">At least 12 characters.</div>
        </div>
        <div className="field">
          <label htmlFor="reset-pw2">Confirm New Password</label>
          <input id="reset-pw2" type="password" value={newPassword2} onChange={e => setNewPassword2(e.target.value)}
            autoComplete="new-password" />
        </div>
        <div className="field">
          <label htmlFor="reset-totp">Authenticator Code</label>
          <input id="reset-totp" value={totpCode} onChange={e => handleTotpChange(e.target.value)}
            placeholder="6 digits" maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
          <div className="field-hint">
            Your password reset also requires your TOTP code to confirm it&apos;s you.
          </div>
        </div>
        <button className="btn btn-gold" onClick={submit} disabled={loading}>
          {loading ? "Resetting…" : "Reset Password"}
        </button>
      </div>
    </div>
  );
}
