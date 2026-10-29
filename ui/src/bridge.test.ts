import {
	afterAll,
	afterEach,
	beforeEach,
	describe,
	expect,
	spyOn,
	test,
} from "bun:test";
import {
	createRepository,
	getBootstrap,
	getScan,
	SecurityApiError,
} from "./bridge.ts";
import type { BootstrapResponse } from "./data.ts";
import type { RyuBridge } from "./ryu.d.ts";

const bootstrap: BootstrapResponse = {
	capabilities: {
		agentVerification: false,
		evidenceLevel: "static-local",
		networkAccess: false,
		patchApplication: false,
	},
	findings: [],
	repositories: [],
	scans: [],
};
let originalWindow: PropertyDescriptor | undefined;
const originalPreconnect = fetch.preconnect;
const fetchSpy = spyOn(globalThis, "fetch");
afterAll(() => fetchSpy.mockRestore());

beforeEach(() => {
	originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
	Object.defineProperty(globalThis, "window", {
		configurable: true,
		writable: true,
		value: undefined,
	});
});
afterEach(() => {
	fetchSpy.mockReset();
	if (originalWindow) {
		Object.defineProperty(globalThis, "window", originalWindow);
	} else {
		Reflect.deleteProperty(globalThis, "window");
	}
});

function installHost(request: RyuBridge["app"]["request"]): void {
	const ryu: RyuBridge = {
		app: { request },
		context: null,
		shell: { subscribeTheme: () => ({ dispose() {} }) },
	};
	Object.defineProperty(globalThis, "window", {
		configurable: true,
		writable: true,
		value: { ryu },
	});
}

function fetchReply(
	reply: Response,
	capture?: (options: RequestInit | undefined) => void
): typeof fetch {
	return Object.assign(
		async (
			_input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1]
		) => {
			capture?.(init);
			return reply.clone();
		},
		{ preconnect: originalPreconnect }
	);
}

describe("Security workbench bridge contracts", () => {
	test("uses the host route and encodes record IDs without a direct network request", async () => {
		const calls: Parameters<RyuBridge["app"]["request"]>[0][] = [];
		installHost(async (input) => {
			calls.push(input);
			return bootstrap;
		});
		expect(await getBootstrap()).toEqual(bootstrap);
		expect(calls).toEqual([
			{ method: "GET", path: "/bootstrap", body: undefined },
		]);
		expect(fetchSpy).not.toHaveBeenCalled();
		await expect(getScan("scan / one")).rejects.toThrow();
		expect(calls[1]?.path).toBe("/scans/scan%20%2F%20one");
	});
	test("GET fallback omits a body and POST carries the original repository path", async () => {
		const requests: RequestInit[] = [];
		fetchSpy.mockImplementation(
			fetchReply(Response.json(bootstrap), (init) => requests.push(init ?? {}))
		);
		expect(await getBootstrap()).toEqual(bootstrap);
		const options = requests[0];
		if (!options) {
			throw new Error("Expected fallback request options");
		}
		expect(Object.hasOwn(options, "body")).toBe(false);
		fetchSpy.mockImplementation(
			fetchReply(
				Response.json({
					branch: "main",
					createdAt: "now",
					fileCount: 0,
					findingCount: 0,
					head: "head",
					id: "repository",
					name: "Workspace",
					path: "/fixture/workspace",
					scanCount: 0,
					status: "ready",
				}),
				(init) => requests.push(init ?? {})
			)
		);
		await createRepository("/fixture/workspace");
		expect(requests[1]?.body).toBe(
			JSON.stringify({ path: "/fixture/workspace" })
		);
		expect(new Headers(requests[1]?.headers).get("content-type")).toBe(
			"application/json"
		);
	});
	test("preserves sidecar refusal status, code and message", async () => {
		fetchSpy.mockImplementation(
			fetchReply(
				Response.json(
					{ error: { code: "permission_denied", message: "Not allowed" } },
					{ status: 403 }
				)
			)
		);
		await expect(getBootstrap()).rejects.toBeInstanceOf(SecurityApiError);
		await expect(getBootstrap()).rejects.toMatchObject({
			status: 403,
			code: "permission_denied",
			message: "Not allowed",
		});
	});
	test("rejects malformed success capabilities before they reach the workbench", async () => {
		fetchSpy.mockImplementation(
			fetchReply(
				Response.json({
					...bootstrap,
					capabilities: { ...bootstrap.capabilities, networkAccess: "true" },
				})
			)
		);
		await expect(getBootstrap()).rejects.toThrow();
	});
});
