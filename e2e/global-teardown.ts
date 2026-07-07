import fs from "fs";

export default async function globalTeardown() {
  const proc = global.__SERVER_PROCESS__;
  if (proc) {
    proc.kill();
    await new Promise<void>((resolve) => proc.on("exit", resolve));
  }
  const dataDir = global.__DATA_DIR__;
  if (dataDir) {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}
