import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../context/AuthContext";

function b64urlToBuffer(b64: string): ArrayBuffer {
  const b64std = b64.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const bin = atob(b64std);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufferToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
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

interface Passkey {
  credentialId: string;
  deviceName:   string;
  createdAt:    string;
}

interface UserEntry {
  username:  string;
  isAdmin:   boolean;
  createdAt: number;
}

export function AccountScreen() {
  const { logout } = useAuth();

  // Delete account
  const [confirmDeleteSelf, setConfirmDeleteSelf]   = useState(false);
  const [deletePassword, setDeletePassword]         = useState("");
  const [deleteError, setDeleteError]               = useState("");
  const [deleteLoading, setDeleteLoading]           = useState(false);

  const [passkeys, setPasskeys]               = useState<Passkey[]>([]);
  const [recoveryCount, setRecoveryCount]     = useState<number | null>(null);
  const [isAdmin, setIsAdmin]                 = useState(false);
  const [currentUsername, setCurrentUsername] = useState("");
  const [users, setUsers]                     = useState<UserEntry[]>([]);
  const [inviteURL, setInviteURL]             = useState("");
  const [inviteError, setInviteError]         = useState("");
  const [currentEmail, setCurrentEmail]       = useState("");
  const [editingEmail, setEditingEmail]       = useState(false);
  const [emailInput, setEmailInput]           = useState("");
  const [emailError, setEmailError]           = useState("");
  const [emailSuccess, setEmailSuccess]       = useState("");
  const [pendingEmail, setPendingEmail]       = useState("");

  // Change password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword]         = useState("");
  const [newPassword2, setNewPassword2]       = useState("");
  const [pwError, setPwError]                 = useState("");
  const [pwSuccess, setPwSuccess]             = useState("");
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[]>([]);
  const [pwLoading, setPwLoading]             = useState(false);
  const [addingPasskey, setAddingPasskey]     = useState(false);
  const [passkeyError, setPasskeyError]       = useState("");

  // Inline confirms
  const [confirmRemovePasskey, setConfirmRemovePasskey] = useState<string | null>(null);
  const [confirmDeleteUser, setConfirmDeleteUser]       = useState<string | null>(null);
  const [confirmRegen, setConfirmRegen]                 = useState(false);

  useEffect(() => { loadData(); }, []);

  async function loadData() {
    const [pkData, rcData, meData, pendingData] = await Promise.all([
      api("GET", "/api/webauthn/credentials"),
      api("GET", "/api/auth/recovery-codes/count"),
      api("GET", "/api/auth/me"),
      api("GET", "/api/auth/email/pending"),
    ]);
    if (Array.isArray(pkData)) setPasskeys(pkData as unknown as Passkey[]);
    if (typeof rcData.remaining === "number") setRecoveryCount(rcData.remaining);
    if (typeof meData.username === "string") setCurrentUsername(meData.username);
    if (typeof meData.email === "string") setCurrentEmail(meData.email);
    if (typeof pendingData.email === "string") setPendingEmail(pendingData.email);
    if (meData.isAdmin === true) {
      setIsAdmin(true);
      loadUsers();
    }
  }

  async function loadUsers() {
    const data = await api("GET", "/api/admin/users");
    if (Array.isArray(data)) setUsers(data as unknown as UserEntry[]);
  }

  async function removePasskey(id: string) {
    const data = await api("DELETE", `/api/webauthn/credentials/${encodeURIComponent(id)}`);
    if (data.error) { setPasskeyError(data.error as string); return; }
    setPasskeys(ps => ps.filter(p => p.credentialId !== id));
    setConfirmRemovePasskey(null);
  }

  async function addPasskey() {
    setPasskeyError(""); setAddingPasskey(true);
    try {
      const opts = await api("POST", "/api/webauthn/add-device/start");
      if (opts.error) { setPasskeyError(opts.error as string); return; }

      const pk = (opts as unknown as { publicKey: Record<string, unknown> }).publicKey;
      const createOpts: PublicKeyCredentialCreationOptions = {
        ...(pk as unknown as PublicKeyCredentialCreationOptions),
        challenge: b64urlToBuffer(pk.challenge as string),
        user: {
          ...(pk.user as PublicKeyCredentialUserEntity),
          id: b64urlToBuffer((pk.user as Record<string, string>).id),
        },
        excludeCredentials: ((pk.excludeCredentials ?? []) as Array<{ type: string; id: string }>).map(c => ({
          type: c.type as PublicKeyCredentialType,
          id: b64urlToBuffer(c.id),
        })),
      };

      const cred = await navigator.credentials.create({ publicKey: createOpts }) as PublicKeyCredential | null;
      if (!cred) { setPasskeyError("Passkey creation cancelled"); return; }

      const attestation = cred.response as AuthenticatorAttestationResponse;
      const body = {
        id: cred.id,
        rawId: bufferToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON:    bufferToB64url(attestation.clientDataJSON),
          attestationObject: bufferToB64url(attestation.attestationObject),
        },
      };

      const result = await api("POST", "/api/webauthn/add-device/finish", body);
      if (result.error) { setPasskeyError(result.error as string); return; }
      await loadData();
    } catch (e) {
      setPasskeyError(e instanceof Error ? e.message : "Passkey registration failed");
    } finally {
      setAddingPasskey(false);
    }
  }

  async function changePassword() {
    setPwError(""); setPwSuccess(""); setNewRecoveryCodes([]);
    if (newPassword.length < 12) return setPwError("New password must be at least 12 characters");
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
    const data = await api("POST", "/api/auth/recovery-codes/regenerate");
    if (data.error) { setConfirmRegen(false); return; }
    setNewRecoveryCodes(data.recoveryCodes as string[]);
    setRecoveryCount(8);
    setPwSuccess("New recovery codes generated:");
    setConfirmRegen(false);
  }

  async function saveEmail() {
    setEmailError(""); setEmailSuccess("");
    const data = await api("PUT", "/api/auth/email", { email: emailInput.trim() });
    if (data.error) return setEmailError(data.error as string);
    setEditingEmail(false);
    if (data.pending) {
      setPendingEmail(emailInput.trim());
    } else {
      setCurrentEmail("");
      setPendingEmail("");
      setEmailSuccess("Email removed.");
    }
  }

  async function cancelPendingEmail() {
    await api("DELETE", "/api/auth/email/pending");
    setPendingEmail("");
  }

  async function deleteUser(username: string) {
    const data = await api("DELETE", `/api/admin/users/${encodeURIComponent(username)}`);
    if (data.error) { setConfirmDeleteUser(null); return; }
    setUsers(us => us.filter(u => u.username !== username));
    setConfirmDeleteUser(null);
  }

  async function deleteSelfAccount() {
    setDeleteError(""); setDeleteLoading(true);
    const data = await api("DELETE", "/api/auth/account", { password: deletePassword });
    setDeleteLoading(false);
    if (data.error) { setDeleteError(data.error as string); return; }
    logout();
  }

  async function generateInvite() {
    setInviteError(""); setInviteURL("");
    const data = await api("POST", "/api/admin/invite");
    if (data.error) { setInviteError(data.error as string); return; }
    setInviteURL(data.url as string);
  }

  return (
    <div className="account-page">
      <div className="account-tag">ACCOUNT MANAGER</div>
      <div className="account-title">Account Settings</div>
      {currentUsername && (
        <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20 }}>
          Signed in as <strong>{currentUsername}</strong>
        </div>
      )}

      {/* Email */}
      <div className="section">
        <div className="section-title">Email</div>
        <div className="card">
          <div aria-live="polite">
            {emailError && <div className="error-msg">{emailError}</div>}
            {emailSuccess && <div className="success-msg">{emailSuccess}</div>}
          </div>
          {pendingEmail && !editingEmail && (
            <div className="field-hint" style={{ marginBottom: 12, color: "var(--muted)" }}>
              Verification sent to <strong>{pendingEmail}</strong> — check your inbox.{" "}
              <button className="btn btn-ghost btn-sm" style={{ display: "inline", padding: "0 4px" }}
                onClick={cancelPendingEmail}>Cancel</button>
            </div>
          )}
          {editingEmail ? (
            <div>
              <div className="field">
                <label htmlFor="email-input">Email address</label>
                <input id="email-input" type="email" value={emailInput} onChange={e => setEmailInput(e.target.value)}
                  autoFocus onKeyDown={e => { if (e.key === "Enter") saveEmail(); }} />
                <div className="field-hint">Used for password reset emails.</div>
              </div>
              <div className="btn-row">
                <button className="btn btn-gold btn-sm" onClick={saveEmail}>Save</button>
                <button className="btn btn-ghost btn-sm" onClick={() => { setEditingEmail(false); setEmailError(""); }}>Cancel</button>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <span style={{ fontSize: 13, color: currentEmail ? "var(--text)" : "var(--muted)" }}>
                {currentEmail || "No email set"}
              </span>
              <button className="btn btn-ghost btn-sm"
                onClick={() => { setEmailInput(currentEmail); setEditingEmail(true); setEmailSuccess(""); }}>
                {currentEmail ? "Change" : "Add email"}
              </button>
            </div>
          )}
        </div>
      </div>

      <hr className="divider" />

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
            {confirmRemovePasskey === pk.credentialId ? (
              <div className="confirm-inline">
                <span className="confirm-inline-text">
                  {passkeys.length === 1 ? "Last passkey — remove anyway?" : "Remove this passkey?"}
                </span>
                <button className="btn btn-danger btn-sm" onClick={() => removePasskey(pk.credentialId)}>Remove</button>
                <button className="btn btn-ghost btn-sm" onClick={() => setConfirmRemovePasskey(null)}>Cancel</button>
              </div>
            ) : (
              <button className="btn btn-danger btn-sm" onClick={() => setConfirmRemovePasskey(pk.credentialId)}>
                Remove
              </button>
            )}
          </div>
        ))}
        {passkeyError && <div className="error-msg" style={{ marginTop: 8 }}>{passkeyError}</div>}
        <button className="btn btn-gold btn-sm" onClick={addPasskey} disabled={addingPasskey} style={{ marginTop: 10 }}>
          {addingPasskey ? "Adding…" : "Add Passkey"}
        </button>
      </div>

      <hr className="divider" />

      {/* Recovery codes */}
      <div className="section">
        <div className="section-title">Recovery Codes</div>
        <div className="card">
          <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 4 }}>
            {recoveryCount !== null
              ? `${recoveryCount} code${recoveryCount === 1 ? "" : "s"} remaining`
              : <span className="spinner" style={{ width: 14, height: 14, borderWidth: 1.5 }} />
            }
          </div>
          <div className="field-hint" style={{ marginBottom: 12 }}>
            Each code works once. If you run low, regenerate them below.
          </div>
          {newRecoveryCodes.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              {pwSuccess && <div className="success-msg">{pwSuccess}</div>}
              <div className="card" style={{ marginTop: 8 }}>
                <div className="code-list">
                  {newRecoveryCodes.map(c => <div key={c} className="code-item">{c}</div>)}
                </div>
                <div className="code-copy-row">
                  <CopyButton text={newRecoveryCodes.join("\n")} label="Copy all" />
                </div>
              </div>
            </div>
          )}
          {confirmRegen ? (
            <div className="confirm-inline">
              <span className="confirm-inline-text">This will invalidate all existing codes. Continue?</span>
              <button className="btn btn-danger btn-sm" onClick={regenerateRecoveryCodes}>Yes, regenerate</button>
              <button className="btn btn-ghost btn-sm" onClick={() => setConfirmRegen(false)}>Cancel</button>
            </div>
          ) : (
            <button className="btn btn-ghost btn-sm" onClick={() => setConfirmRegen(true)}>
              Regenerate Codes
            </button>
          )}
        </div>
      </div>

      <hr className="divider" />

      {/* Change password */}
      <div className="section">
        <div className="section-title">Change Password</div>
        <div className="card">
          <div aria-live="polite">
            {pwError && <div className="error-msg">{pwError}</div>}
            {pwSuccess && newRecoveryCodes.length === 0 && <div className="success-msg">{pwSuccess}</div>}
          </div>
          <div className="field">
            <label htmlFor="pw-current">Current Password</label>
            <input id="pw-current" type="password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} autoComplete="current-password" />
          </div>
          <div className="field">
            <label htmlFor="pw-new">New Password</label>
            <input id="pw-new" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} autoComplete="new-password" />
            <div className="field-hint">At least 12 characters.</div>
          </div>
          <div className="field">
            <label htmlFor="pw-new2">Confirm New Password</label>
            <input id="pw-new2" type="password" value={newPassword2} onChange={e => setNewPassword2(e.target.value)} autoComplete="new-password" />
          </div>
          <button className="btn btn-gold" onClick={changePassword} disabled={pwLoading}>
            {pwLoading ? "Changing…" : "Change Password"}
          </button>
        </div>
      </div>

      <hr className="divider" />

      {/* Admin: user management */}
      {isAdmin && (
        <>
          <div className="section">
            <div className="section-title">Users</div>
            {users.map(u => (
              <div key={u.username} className="card passkey-row">
                <div>
                  <div className="passkey-name">
                    {u.username}
                    {u.isAdmin && (
                      <span style={{ marginLeft: 6, fontSize: 11, color: "var(--muted)", textTransform: "uppercase" }}>admin</span>
                    )}
                  </div>
                  <div className="passkey-date">Joined {new Date(u.createdAt).toLocaleDateString()}</div>
                </div>
                {u.username !== currentUsername && (
                  confirmDeleteUser === u.username ? (
                    <div className="confirm-inline">
                      <span className="confirm-inline-text">Delete {u.username}?</span>
                      <button className="btn btn-danger btn-sm" onClick={() => deleteUser(u.username)}>Delete</button>
                      <button className="btn btn-ghost btn-sm" onClick={() => setConfirmDeleteUser(null)}>Cancel</button>
                    </div>
                  ) : (
                    <button className="btn btn-danger btn-sm" onClick={() => setConfirmDeleteUser(u.username)}>
                      Delete
                    </button>
                  )
                )}
              </div>
            ))}
            {inviteError && <div className="error-msg" style={{ marginTop: 8 }}>{inviteError}</div>}
            {inviteURL && (
              <div className="card" style={{ marginTop: 12 }}>
                <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8 }}>
                  Share this invite link — expires in 48 hours:
                </div>
                <div className="invite-url-row">
                  <input readOnly value={inviteURL} onClick={e => (e.target as HTMLInputElement).select()} />
                  <CopyButton text={inviteURL} />
                </div>
              </div>
            )}
            <button className="btn btn-gold btn-sm" style={{ marginTop: 10 }} onClick={generateInvite}>
              Generate Invite Link
            </button>
          </div>

          <hr className="divider" />
        </>
      )}

      {/* Delete account */}
      <div className="section">
        <div className="section-title" style={{ color: "var(--danger, #c0392b)" }}>Danger Zone</div>
        <div className="card">
          {confirmDeleteSelf ? (
            <div>
              <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 12 }}>
                This will permanently delete your account and all associated data. Enter your password to confirm.
              </p>
              <div aria-live="polite">
                {deleteError && <div className="error-msg">{deleteError}</div>}
              </div>
              <div className="field">
                <label htmlFor="delete-password">Password</label>
                <input id="delete-password" type="password" value={deletePassword}
                  onChange={e => setDeletePassword(e.target.value)} autoFocus
                  onKeyDown={e => { if (e.key === "Enter" && deletePassword) deleteSelfAccount(); }} />
              </div>
              <div className="btn-row">
                <button className="btn btn-danger" onClick={deleteSelfAccount}
                  disabled={deleteLoading || !deletePassword}>
                  {deleteLoading ? "Deleting…" : "Delete My Account"}
                </button>
                <button className="btn btn-ghost btn-sm"
                  onClick={() => { setConfirmDeleteSelf(false); setDeletePassword(""); setDeleteError(""); }}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <span style={{ fontSize: 13, color: "var(--muted)" }}>Permanently delete your account and all data.</span>
              <button className="btn btn-danger btn-sm" onClick={() => setConfirmDeleteSelf(true)}>
                Delete Account
              </button>
            </div>
          )}
        </div>
      </div>

      <hr className="divider" />

      <div style={{ display: "flex", gap: 8 }}>
        <a href="/" className="btn btn-ghost" style={{ textDecoration: "none" }}>Home</a>
        <button className="btn btn-ghost" onClick={logout}>Sign Out</button>
      </div>
    </div>
  );
}
