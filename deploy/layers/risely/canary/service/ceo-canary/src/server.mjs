import { fileURLToPath } from "node:url";
import { productionRuntimeScopeFromEnv } from "../../../runtime-scope/index.mjs";
import { assertIngressConfig } from "./auth.mjs";
import { createCanaryHttpServer } from "./http.mjs";
import { PostgresCanaryStore } from "./postgres-store.mjs";
import { CanaryService } from "./service.mjs";

export async function startServer(env = process.env, options = {}) {
  if (env.CANARY_MUTATIONS_ENABLED !== "0") {
    throw new Error("CANARY_MUTATIONS_ENABLED must remain 0 until a reviewed caller is deployed");
  }
  if (env.CANARY_PROVIDER_EXECUTION_ENABLED !== "0") {
    throw new Error("CANARY_PROVIDER_EXECUTION_ENABLED must remain 0 in the CEO canary foundation");
  }
  const port = Number(env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
  const scope = productionRuntimeScopeFromEnv(env);
  const ingressConfig = assertIngressConfig({
    secret: env.CANARY_INGRESS_SECRET,
    issuer: env.CANARY_INGRESS_ISSUER,
    audience: env.CANARY_INGRESS_AUDIENCE,
    keyId: env.CANARY_INGRESS_KEY_ID,
  });
  const store = PostgresCanaryStore.fromEnv(env, scope);
  let server;
  try {
    await store.initialize();
    const service = new CanaryService({ store, scope });
    server = createCanaryHttpServer({ service, store, ingressConfig });
    await new Promise((resolve, reject) => {
      const onError = (error) => reject(error);
      const onListening = () => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.listen(port, "0.0.0.0", onListening);
    });
  } catch (error) {
    await store.close().catch(() => {});
    throw error;
  }
  let shutdownPromise;
  const shutdown = () => {
    if (shutdownPromise) return shutdownPromise;
    shutdownPromise = (async () => {
      const force = setTimeout(() => server.closeAllConnections(), 8000);
      force.unref();
      server.closeIdleConnections();
      await new Promise((resolve) => server.close(resolve));
      clearTimeout(force);
      await store.close();
    })();
    return shutdownPromise;
  };
  const signals = ["SIGTERM", "SIGINT"];
  if (options.installSignalHandlers !== false) {
    for (const signal of signals) process.once(signal, shutdown);
  }
  return {
    server,
    store,
    shutdown: async () => {
      for (const signal of signals) process.removeListener(signal, shutdown);
      await shutdown();
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer().catch(() => {
    process.stderr.write("CEO canary startup failed\n");
    process.exitCode = 1;
  });
}
