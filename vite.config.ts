import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/accounts/",
  server: {
    port: 5174,
    proxy: {
      "/accounts/api": { target: "http://localhost:3001", changeOrigin: false, rewrite: (p) => p.replace(/^\/accounts/, "") },
      "/accounts/authorize": { target: "http://localhost:3001", changeOrigin: false, rewrite: (p) => p.replace(/^\/accounts/, "") },
      "/accounts/token": { target: "http://localhost:3001", changeOrigin: false, rewrite: (p) => p.replace(/^\/accounts/, "") },
      "/accounts/.well-known": { target: "http://localhost:3001", changeOrigin: false, rewrite: (p) => p.replace(/^\/accounts/, "") },
    },
  },
  build: {
    outDir: "dist",
  },
});
