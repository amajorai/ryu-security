import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const here = dirname(fileURLToPath(import.meta.url));
const localToken = process.env.RYU_SECURITY_DEV_TOKEN;

export default defineConfig({
	root: here,
	base: "./",
	plugins: [react(), viteSingleFile()],
	server: {
		proxy: {
			"/api/security": {
				headers: localToken
					? { Authorization: `Bearer ${localToken}` }
					: undefined,
				target: "http://127.0.0.1:8044",
				changeOrigin: false,
			},
		},
	},
	build: {
		outDir: "dist",
		emptyOutDir: true,
		target: "esnext",
		cssCodeSplit: false,
		assetsInlineLimit: Number.POSITIVE_INFINITY,
		modulePreload: { polyfill: false },
		rollupOptions: {
			input: { security: resolve(here, "index.html") },
			output: { inlineDynamicImports: true },
		},
	},
});
