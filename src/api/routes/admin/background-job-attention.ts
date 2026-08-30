import { sendJson } from "../../http.ts";
import { audit, requireScopedAdmin } from "../shared.ts";
import type { ApiCtx } from "../route.ts";
import { parseScopeId } from "../../../types.ts";

export async function listBackgroundJobAttention(ctx: ApiCtx): Promise<void> {
  const authz = await requireScopedAdmin(ctx);
  if (!authz) return;
  if (parseScopeId(authz.scope).kind !== "org") {
    return sendJson(ctx.res, 403, { error: "forbidden", message: "background job attention requires org scope" });
  }
  const requested = ctx.url.searchParams.get("limit");
  const limit = requested === null ? 50 : Number(requested);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    return sendJson(ctx.res, 400, { error: "bad_request", message: "limit must be an integer from 1 through 100" });
  }
  const rows = (await ctx.deps.backgroundJobAttention?.list(limit)) ?? [];
  audit(ctx.deps, {
    principalId: authz.actor.id,
    action: "background_jobs.attention.read",
    resource: "background-jobs",
    scopeLabel: authz.scope,
  });
  return sendJson(ctx.res, 200, { rows, limit });
}
