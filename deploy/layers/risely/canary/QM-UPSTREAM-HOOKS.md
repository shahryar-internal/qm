# QM upstream hooks required by the CEO canary

The Risely repository is a private QM fork, so core files must remain byte-identical to upstream. The two generic hooks below belong in upstream QM. They contain no Risely names, credentials, provider effects, or organization data.

## Slack artifact provider

The existing QM Slack receiver must remain the only Socket Mode connection for an app. A second connection using the same app is unsafe because Slack can deliver an event to either connection.

Add a generic optional artifact provider to the existing Slack startup wiring:

```ts
interface SlackArtifactActionProvider {
  claimDeliveries(input: { limit: number; leaseMs: number }): Promise<readonly SlackArtifactDeliveryClaim[]>;

  confirmDelivery(input: SlackArtifactDeliveryReceipt): Promise<"confirmed" | "already_confirmed" | "rejected">;

  releaseDelivery(input: {
    claimRef: string;
    reason: "slack_failed" | "binding_failed" | "invalid_delivery";
  }): Promise<void>;

  markDeliveryOutcomeUnknown(input: {
    claimRef: string;
    attemptRef: string;
    observedAt: string;
  }): Promise<"held_for_reconciliation" | "already_held" | "rejected">;

  enqueueInteraction(
    input: SlackArtifactInteraction,
  ): Promise<
    | { status: "accepted"; replacement: SlackArtifactCard }
    | { status: "unknown" | "expired" | "replayed" | "binding_mismatch" }
    | { status: "unavailable" }
  >;
}
```

Suggested upstream files:

- Add `src/slack/artifacts.ts`.
- Extend `src/slack/index.ts` and the upstream startup wiring with an optional provider.
- Add focused artifact tests and preserve the existing Slack integration tests.

Use one fixed action ID, `qm_artifact_action_v1`. Its value contains only an opaque `interactionRef`. A card cannot choose action IDs or include raw Block Kit. The handler acknowledges immediately, then sends the observed team, user, channel, and message timestamp to the provider. The provider performs durable exact binding, expiry, and one-use replay checks. QM must not execute Gmail, LinkedIn, CRM, or any other provider effect in the interaction handler.

Delivery claims carry exact team/destination, artifact ID/revision, a stable delivery ID, an opaque lease, and a typed card. Slack receives the stable delivery ID as `client_msg_id`. A returned Slack timestamp must be confirmed against the claim before the delivery becomes final. Missing providers preserve current QM behavior and register no new action handler.

If Slack returns an ambiguous result, QM must call `markDeliveryOutcomeUnknown`. That transition durably prevents lease expiry, reclaim, release, or retry until a separate reconciliation path proves whether Slack accepted the message. It must never treat a timeout or disconnected response as a normal failed delivery.

Required tests cover one Socket Mode client, deterministic rendering, fixed action registration, ack-before-provider behavior, exact observed binding, replay/expiry/mismatch rejection, provider exceptions, message-specific updates, raw-block rejection, durable outcome-unknown hold and reconciliation, shutdown, and existing approval/delivery compatibility.

## Web workflow-artifact renderer

Transport a workflow card as an existing delivered file artifact with MIME:

```text
application/vnd.qm.workflow-artifact+json;v=1
```

The existing assistant delivery replay and authenticated file-content route preserve session ownership and viewer authorization. The renderer must consume the file only through that route.

Suggested upstream files:

- Add a generic registry module under the web UI.
- Add one declarative Lit workflow-artifact element.
- Route only the exact workflow MIME from the existing chat file renderer.

```ts
interface WorkflowArtifactEnvelope {
  version: 1;
  renderer: string;
  fallbackText: string;
  payload: unknown;
}

interface WorkflowArtifactRenderer<T> {
  type: string;
  decode(payload: unknown): T;
  toCard(value: T): WorkflowArtifactCard;
}

interface WorkflowArtifactCard {
  heading: string;
  summary?: string;
  status?: {
    label: string;
    tone: "neutral" | "info" | "success" | "warning" | "danger";
  };
  sections?: readonly {
    key: string;
    label: string;
    items: readonly { label?: string; value: string; href?: string }[];
  }[];
  links?: readonly { label: string; href: string }[];
}
```

The component fetches with `no-store`, refuses redirects, requires the exact MIME, caps the response at 128 KiB, and aborts when disconnected. Envelope and card output both receive strict validation with bounded depth, nodes, strings, and lists. Links allow same-origin or credential-free HTTPS only. Values render through Lit text and property bindings; raw HTML, Markdown, dynamic imports, renderer-selected tags, and effectful controls are forbidden in version one.

Unknown renderers, invalid artifacts, decoder failures, and network failures show a generic fallback plus the already-authorized original-file link. Tests cover registry lifecycle, hostile payloads, URL policy, decoder failures, output revalidation, authenticated fetch, abort/size/MIME handling, literal HTML rendering, accessibility, responsive layout, history replay, settled-row caching, and ordinary-file regression.

## Activation order

1. Land and release the generic upstream hooks through the upstream contribution workflow.
2. Sync the private Risely fork from upstream without rebasing.
3. Register the Risely deployment-owned decoder and provider through an upstream-sanctioned wiring seam.
4. Run the required live dev-instance Firefox QA and attach desktop/mobile and Slack demos to the upstream review.
5. Enable display-only artifacts first. Keep effectful interactions disabled until the separate durable identity and action bridge passes review.

Module-global registries, arbitrary callback URLs, a second same-app Socket Mode connection, or a source-auth caller impersonating a web principal are not acceptable substitutes.
