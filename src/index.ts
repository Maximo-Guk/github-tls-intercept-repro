import { Container, getContainer } from "@cloudflare/containers";
import { Hono } from "hono";

export class ReproContainer extends Container<Env> {
	// The container's plain-HTTP server (landing page + /probe + the github
	// reverse proxy) listens on 8080. The dirty-close TLS listener (:8443) is the
	// crux of the repro and is NOT reachable through a deployed Worker: the
	// Cloudflare edge re-terminates TLS in front of the Worker and would itself
	// send a clean close_notify, masking the bug. The container's SELF-TEST
	// (which hits its own :8443 internally) is what makes the GnuTLS -110 show up
	// in logs regardless of environment. See README.md.
	defaultPort = 8080;
	sleepAfter = "10m";

	override onStart() {
		console.log("repro container started");
	}
	override onError(error: unknown) {
		console.log("repro container error:", error);
	}
}

const app = new Hono<{ Bindings: Env }>();

// Run both probes in the container and surface the result to `wrangler tail` /
// dashboard observability via console.log, then return the JSON.
app.get("/probe", async (c) => {
	const container = getContainer(c.env.REPRO_CONTAINER);
	const res = await container.fetch(new Request("http://container/probe"));
	const report = await res.json();
	console.log("gh-tls-repro probe:", JSON.stringify(report));
	return c.json(report);
});

// Everything else (landing page "/", github reverse-proxy paths) forwards to the
// container's :8080 server.
app.all("*", async (c) => {
	const container = getContainer(c.env.REPRO_CONTAINER);
	return await container.fetch(c.req.raw);
});

export default app;
