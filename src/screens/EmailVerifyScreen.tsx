import { useEffect, useState } from "react";
import { api } from "../api";

interface Props {
  token: string;
  onDone: () => void;
}

export function EmailVerifyScreen({ token, onDone }: Props) {
  const [status, setStatus] = useState<"loading" | "ok" | "error">("loading");
  const [email, setEmail]   = useState("");
  const [error, setError]   = useState("");

  useEffect(() => {
    api("GET", `/api/auth/email/verify?token=${encodeURIComponent(token)}`, undefined, false).then(data => {
      if (data.error) {
        setError(data.error as string);
        setStatus("error");
      } else {
        setEmail(data.email as string);
        setStatus("ok");
      }
    });
  }, [token]);

  return (
    <div className="screen">
      <div className="screen-box">
        <div className="screen-tag">ACCOUNT MANAGER</div>
        {status === "loading" && (
          <div style={{ display: "flex", justifyContent: "center", margin: "32px 0" }}>
            <div className="spinner" />
          </div>
        )}
        {status === "ok" && (
          <>
            <div className="screen-title">Email verified</div>
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20 }}>
              <strong>{email}</strong> has been saved to your account.
            </p>
            <button className="btn btn-gold" onClick={onDone}>Continue</button>
          </>
        )}
        {status === "error" && (
          <>
            <div className="screen-title">Verification failed</div>
            <div className="error-msg" style={{ marginBottom: 16 }}>{error}</div>
            <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 20 }}>
              The link may have expired or already been used. You can request a new one from Account Settings.
            </p>
            <button className="btn btn-ghost" onClick={onDone}>Continue</button>
          </>
        )}
      </div>
    </div>
  );
}
