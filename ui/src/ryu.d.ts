import type { RyuAppBridge } from "@ryu/app-host/app-bridge";

export interface RyuShellSubscription {
	dispose(): void;
}

export interface RyuShell {
	subscribeTheme(options: {
		onChange: (tokens: Record<string, string>) => void;
	}): RyuShellSubscription;
}

export interface SecurityAppRequest {
	body?: unknown;
	method?: "GET" | "POST";
	path: string;
}

export interface RyuBridge extends RyuAppBridge {
	app: { request(input: SecurityAppRequest): Promise<unknown> };
	context?: { screen?: string } | null;
	shell: RyuShell;
}

declare global {
	interface Window {
		ryu?: RyuBridge;
	}
}
