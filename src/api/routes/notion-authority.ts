import { sendJson } from "../http.ts";
import type { BaseCtx, Route } from "./route.ts";

export const notionAuthorityRoutes: ReadonlyArray<Route<BaseCtx>> = [
  {
    method: "GET",
    path: "/.well-known/jwks.json",
    auth: "public",
    handle: ({ res, deps }) => {
      if (!deps.notionAuthorityPublic) {
        sendJson(res, 404, { error: "not_found" });
        return;
      }
      sendJson(res, 200, deps.notionAuthorityPublic.jwks);
    },
  },
  {
    method: "GET",
    path: "/.well-known/notion-read-authority-readiness.json",
    auth: "public",
    handle: ({ res, deps }) => {
      if (!deps.notionAuthorityPublic) {
        sendJson(res, 404, { error: "not_found" });
        return;
      }
      sendJson(res, 200, deps.notionAuthorityPublic.readiness);
    },
  },
];
