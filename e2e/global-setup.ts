import { spawn } from "child_process";
import os from "os";
import fs from "fs";
import path from "path";

declare global {
  var __SERVER_PROCESS__: ReturnType<typeof spawn> | undefined;
  var __DATA_DIR__: string | undefined;
}

export default async function globalSetup() {
  const externalBase = process.env.E2E_BASE_URL;

  if (externalBase) {
    // Server is already running externally (e.g. Docker Compose).
    // AM_DATA_DIR must be set in the environment so queryDB can find the DB file.
    console.log(`[e2e] Using external server at ${externalBase}`);
    await waitForServer(externalBase);
    return;
  }

  // ── Spawn our own isolated server ────────────────────────────────────────────
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "am-e2e-"));
  global.__DATA_DIR__ = dataDir;
  process.env.AM_DATA_DIR = dataDir;

  await new Promise<void>((resolve, reject) => {
    // In Docker the binary is pre-built and E2E_SERVER_BIN points at it.
    // Locally we fall back to "go run ./cmd/server" so no extra setup is needed.
    const serverBin = process.env.E2E_SERVER_BIN;
    const [cmd, cmdArgs]: [string, string[]] = serverBin
      ? [serverBin, []]
      : ["go", ["run", "./cmd/server"]];

    const proc = spawn(cmd, cmdArgs, {
      env: {
        ...process.env,
        PORT: "4001",
        DATA_DIR: dataDir,
        JWT_ISSUER: "http://localhost:4001",
        WEBAUTHN_RP_ID: "localhost",
        WEBAUTHN_RP_NAME: "Test",
        CSRF_SECRET: "e2e-csrf-secret",
        GAMEBACKLOG_REDIRECT_URI: "http://localhost:3000/auth/callback",
        RATE_LIMIT_MAX: "1000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    global.__SERVER_PROCESS__ = proc;

    const timeout = setTimeout(() => {
      reject(new Error("Server did not start within 30 seconds"));
    }, 30_000);

    function onOutput(chunk: Buffer) {
      const text = chunk.toString();
      process.stdout.write("[server] " + text);
      if (text.includes("listening on")) {
        clearTimeout(timeout);
        resolve();
      }
    }
    proc.stdout?.on("data", onOutput);
    // Go's log package writes to stderr by default — check there too.
    proc.stderr?.on("data", onOutput);
    proc.on("error", reject);
    proc.on("exit", (code) => {
      if (code !== 0 && code !== null) {
        clearTimeout(timeout);
        reject(new Error(`Server exited with code ${code}`));
      }
    });
  });
}

/** Poll the server's status endpoint until it responds or we time out. */
async function waitForServer(base: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/api/setup/status`);
      if (res.ok) return;
    } catch {
      // Not up yet — keep polling.
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Server at ${base} did not respond within ${timeoutMs / 1000}s`);
}
