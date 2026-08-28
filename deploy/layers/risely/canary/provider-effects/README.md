# Provider effect policy

This public layer defines the profile-bound write policy shared by provider adapters. It does not hold credentials, contact providers, reserve effects, or authorize production execution.

The CEO profile currently declares six prospective write capabilities. Gmail draft creation, managed primary-calendar create and update, private Notion upsert, and private CEO Slack posting declare automatic mode. Gmail draft send declares an exact one-use approval mode bound to the current draft revision. These modes are hashed policy, not execution authority. Calendar update requires an existing agent-ownership receipt and provider ETag. Notion is fixed to the attested private CEO root. Slack is fixed to the verified CEO direct-message audience. Gmail read evidence remains a source alias that must resolve to the same signed Google subject and mailbox before it can support a write.

Every proposal must use the profile's exact provider owner, principal, agent, credential owner, audience, time limit, target, payload, and content hashes. All policies remain non-executable until signed provider identity, durable effect authority, reconciliation, production credentials, and the external activation gates exist. Unknown outcomes are never retried without durable reconciliation.

New roles reuse `createProviderEffectPolicySuite` with a separately branded deployment profile. Role-specific identities, owners, audiences, grants, and capabilities must remain in that profile; adapters must not add global identity aliases.
