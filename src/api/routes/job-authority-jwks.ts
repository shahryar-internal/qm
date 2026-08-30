import type { JsonWebKey } from "node:crypto";
import { sendJson } from "../http.ts";
import type { BaseCtx, Route } from "./route.ts";

type JobAuthorityJwksDeps = BaseCtx["deps"] & {
  jobAuthorityJwks?: () => Readonly<{ keys: readonly Readonly<JsonWebKey>[] }>;
};

export const jobAuthorityJwksRoutes: ReadonlyArray<Route<BaseCtx>> = [
  {
    method: "GET",
    path: "/.well-known/job-authority-jwks.json",
    auth: "public",
    handle: ({ res, deps }) => {
      const jwks = (deps as JobAuthorityJwksDeps).jobAuthorityJwks?.();
      if (!jwks) return sendJson(res, 404, { error: "not_found" });
      res.setHeader("cache-control", "public, max-age=300, stale-while-revalidate=300");
      return sendJson(res, 200, jwks);
    },
  },
];
