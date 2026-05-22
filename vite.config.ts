import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/",
  server: {
    port: 5174,
    proxy: {
      "/api": { target: "http://localhost:3001", changeOrigin: false },
      "/authorize": { target: "http://localhost:3001", changeOrigin: false },
      "/token": { target: "http://localhost:3001", changeOrigin: false },
      "/.well-known": { target: "http://localhost:3001", changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
  },
});
