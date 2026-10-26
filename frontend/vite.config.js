import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the browser talks to this dev server, which forwards /api to the Shield server (Caddy, HTTPS).
// "secure: false" accepts Caddy's local certificate. Change the target with:  SHIELD_API=https://shield.lab npm run dev
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": { target: process.env.SHIELD_API || "https://localhost", changeOrigin: true, secure: false },
    },
  },
  test: { environment: "jsdom", globals: true },
});
