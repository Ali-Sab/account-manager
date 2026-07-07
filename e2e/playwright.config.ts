import { defineConfig, devices } from "@playwright/test";
import path from "path";
import { spawn, ChildProcess } from "child_process";
import os from "os";
import fs from "fs";

// Build the Go binary once before tests run.
// The binary is started per-worker in globalSetup.
export default defineConfig({
  testDir: ".",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:4001",
    trace: "on-first-retry",
  },
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
