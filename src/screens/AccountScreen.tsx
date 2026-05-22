import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../context/AuthContext";

interface Passkey {
  credentialId: string;
  deviceName:   string;
  createdAt:    string;
}

export function AccountScreen() {
  const { logout } = useAuth();

  const [passkeys, setPasskeys]               = useState<Passkey[]>([]);
  const [recoveryCount, setRecoveryCount]     = useState<number | null>(null);

  // Change password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword]         = useState("");
  const [newPassword2, setNewPassword2]       = useState("");
  const [pwError, setPwError]                 = useState("");
  const [pwSuccess, setPwSuccess]             = useState("");
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[]>([]);
  const [pwLoading, setPwLoading]             = useState(false);

  useEffect(() => { loadData(); }, []);

  async function loadData() {
    const [pkData, rcData] = await Promise.all([
      api("GET", "/api/webauthn/credentials"),
      api("GET", "/api/auth/recovery-codes/count"),
    ]);
    if (Array.isArray(pkData)) setPasskeys(pkData as unknown as Passkey[]);
    if (typeof rcData.remaining === "number") setRecoveryCount(rcData.remaining);
  }

  async function removePasskey(id: string) {
    if (!confirm("Remove this passkey?")) return;
    const data = await api("DELETE", `/api/webauthn/credentials/${encodeURIComponent(id)}`);
    if (data.error) return alert(data.error as string);
    setPasskeys(ps => ps.filter(p => p.credentialId !== id));
  }

  async function changePassword() {
    setPwError(""); setPwSuccess(""); setNewRecoveryCodes([]);
    if (newPassword.length < 6) return setPwError("New password must be at least 6 characters");
    if (newPassword !== newPassword2) return setPwError("Passwords do not match");
    setPwLoading(true);
    const data = await api("POST", "/api/auth/change-password", { currentPassword, newPassword });
    setPwLoading(false);
    if (data.error) return setPwError(data.error as string);
    setPwSuccess("Password changed. New recovery codes:");
    setNewRecoveryCodes(data.recoveryCodes as string[]);
    setCurrentPassword(""); setNewPassword(""); setNewPassword2("");
  }

  async function regenerateRecoveryCodes() {
    if (!confirm("This will invalidate all existing recovery codes. Continue?")) return;
    const data = await api("POST", "/api/auth/recovery-codes/regenerate");
    if (data.error) return alert(data.error as string);
    setNewRecoveryCodes(data.recoveryCodes as string[]);
    setRecoveryCount(8);
    setPwSuccess("New recovery codes generated:");
  }

  return (
    <div className="account-page">
      <div className="account-tag">ACCOUNT MANAGER</div>
      <div className="account-title">Account Settings</div>

      {/* Passkeys */}
      <div className="section">
        <div className="section-title">Passkeys</div>
        {passkeys.length === 0 && (
          <div className="card" style={{ color: "var(--muted)", fontSize: 13 }}>No passkeys registered.</div>
        )}
        {passkeys.map(pk => (
          <div key={pk.credentialId} className="card passkey-row">
            <div>
              <div className="passkey-name">{pk.deviceName}</div>
              <div className="passkey-date">Added {new Date(pk.createdAt).toLocaleDateString()}</div>
            </div>
            <button className="btn btn-danger btn-sm" onClick={() => removePasskey(pk.credentialId)}
              disabled={passkeys.length <= 1}>
              Remove
            </button>
          </div>
        ))}
      </div>

      <hr className="divider" />

      {/* Recovery codes */}
      <div className="section">
        <div className="section-title">Recovery Codes</div>
        <div className="card">
          <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 10 }}>
            {recoveryCount !== null ? `${recoveryCount} code${recoveryCount === 1 ? "" : "s"} remaining` : "Loading..."}
          </div>
          {newRecoveryCodes.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              {pwSuccess && <div className="success-msg">{pwSuccess}</div>}
              <div className="card" style={{ marginTop: 8 }}>
                {newRecoveryCodes.map(c => (
                  <div key={c} style={{ fontFamily: "monospace", fontSize: 13, padding: "2px 0" }}>{c}</div>
                ))}
              </div>
            </div>
          )}
          <button className="btn btn-ghost btn-sm" onClick={regenerateRecoveryCodes}>
            Regenerate Codes
          </button>
        </div>
      </div>

      <hr className="divider" />

      {/* Change password */}
      <div className="section">
        <div className="section-title">Change Password</div>
        <div className="card">
          {pwError && <div className="error-msg">{pwError}</div>}
          {pwSuccess && newRecoveryCodes.length === 0 && <div className="success-msg">{pwSuccess}</div>}
          <div className="field">
            <label>Current Password</label>
            <input type="password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} />
          </div>
          <div className="field">
            <label>New Password</label>
            <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
          </div>
          <div className="field">
            <label>Confirm New Password</label>
            <input type="password" value={newPassword2} onChange={e => setNewPassword2(e.target.value)} />
          </div>
          <button className="btn btn-gold" onClick={changePassword} disabled={pwLoading}>
            Change Password
          </button>
        </div>
      </div>

      <hr className="divider" />

      <button className="btn btn-ghost" onClick={logout}>Sign Out</button>
    </div>
  );
}
