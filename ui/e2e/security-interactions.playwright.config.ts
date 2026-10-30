import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const appRoot = path.resolve(import.meta.dirname, "..");
const baseURL = "http://127.0.0.1:4590";

export default defineConfig({
	testDir: import.meta.dirname,
	testMatch: "security-interactions.spec.ts",
	fullyParallel: false,
	workers: 1,
	reporter: "list",
	outputDir: "/tmp/ryu-security-interactions-playwright-results",
	use: {
		...devices["Desktop Chrome"],
		baseURL,
		viewport: { width: 1440, height: 960 },
	},
	webServer: {
		command:
			"bun run vite --config=vite.config.ts --host 127.0.0.1 --port 4590 --strictPort",
		cwd: appRoot,
		url: baseURL,
		reuseExistingServer: false,
		timeout: 120_000,
	},
});
