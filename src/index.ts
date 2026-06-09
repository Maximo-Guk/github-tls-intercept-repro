import { Container, getContainer } from "@cloudflare/containers";
import { Hono } from "hono";

export class ReproContainer extends Container<Env> {
	// The plain-HTTP proxy + landing page listens on 8080. The dirty-close TLS
	// listener (:8443) is the point of this repro and is NOT reachable through a
	// deployed Worker, because Cloudflare's edge re-terminates TLS and would
	// itself send a clean close_notify — masking the bug. To observe the actual
	// GnuTLS -110 failure you must hit the container directly (see README).
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

// Forward everything to the container's :8080 plain-HTTP proxy (the working
// "fix" path). This is minimal scaffolding only — the repro itself is run
// against the container directly; see README.md.
app.all("*", async (c) => {
	const container = getContainer(c.env.REPRO_CONTAINER);
	return await container.fetch(c.req.raw);
});

export default app;
