import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const frontendRoot = dirname(fileURLToPath(import.meta.url));
const fixturesRoot = resolve(frontendRoot, "..", "fixtures");

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { fs: { allow: [frontendRoot, fixturesRoot] } },
});
