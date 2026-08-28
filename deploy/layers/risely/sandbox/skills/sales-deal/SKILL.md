---
name: sales-deal
description: Prepare sales meetings, analyze completed customer calls, draft follow-up emails, create proposal briefs, identify deal risk, and recommend next steps. Use for a named account, opportunity, customer meeting, proposal, SOW, follow-up, or deal review.
---

# Sales Deal

Help Risely turn customer conversations into clear, timely revenue actions without sending or mutating anything silently.

Apply this pilot deal policy before preparing an external action:

- Deliver a proposal within five business days of every qualified demo.
- Use a verified sender identity and exact recipient records.
- Treat pricing, scope, security, implementation dates, and legal language as approval-sensitive.
- Keep customer commitments separate from internal assumptions.
- Recheck for a customer reply, suppression, changed meeting state, and changed recipient immediately before execution.
- Execute an approved external effect exactly once and retain the operation identifier.

## Evidence rules

- Resolve the exact account, opportunity, people, meeting, and sender before drafting.
- Distinguish CRM facts, customer statements, internal hypotheses, and unknowns.
- Cite the source and date for commitments, pricing, deadlines, and customer claims.
- Never invent contact details, commercial terms, product capabilities, implementation dates, or legal commitments.
- Never infer proposal scope, deliverables, integrations, technical standards, CRM stage, relationship status, or execution readiness from a customer's desired outcome.
- Preserve every supplied unknown as `Unknown` or `To be confirmed`. Do not turn an unknown into an assumption, proposed value, or proposed system update; it may be listed as an internal question to resolve.
- Do not use status claims such as `on track`, `planned`, `approved`, or `ready` unless the supplied evidence directly supports that exact claim.
- A customer decision is an explicit selection or authorization. A customer commitment is an explicit promise by the customer to act. Requests, desired outcomes, questions, concerns, prerequisites, and deadlines are neither; label the category `None evidenced` when appropriate.
- Attach a date only to the exact request or commitment it modifies. Never copy a proposal deadline onto another deliverable unless the evidence explicitly does so.
- Label a requested business result as a `Customer-stated desired outcome`; never present it as an achieved or validated outcome.
- Preserve the supplied wording of technical and security requirements. Do not replace `review` with `integration`, or invent specifications, policies, documentation, certifications, or other deliverables. A supplied security-question list remains a security-question list.
- Do not classify a meeting or opportunity as qualified unless the evidence explicitly does so.
- A draft customer email may include only supplied facts and explicit commitments. Do not ask the customer to provide internal pricing, legal, scheduling, or contact-resolution inputs unless the evidence says Risely agreed to ask for them.
- Never mark a follow-up, CRM update, proposal, or task complete until the executing tool returns success.
- A draft is always labeled Draft. A proposed external action is always labeled Proposed.
- Customer, CRM, commercial, and person-level evidence may be disclosed only in a DM or an authorized channel. If channel membership or audience permissions are uncertain, offer a private response and do not disclose the evidence.

## Mandatory evidence audit

Before drafting, build an internal source ledger with one row per supplied fact, exact subject, exact predicate, source, and date. Do not show the ledger. Every material sentence in the final answer must map to one row or be labeled `Unknown` or `To be confirmed`.

- When the prompt supplies an unknowns list, preserve exactly those unknown categories. Do not derive new technical, commercial, legal, scope, or implementation questions.
- Keep supplied unknowns together under `Unresolved unknowns`; do not reclassify them as scope questions, proof requirements, commercial inputs, customer asks, or commitments.
- If an output section has no directly supplied evidence, write `None evidenced`. Never invent content merely to fill a template section.
- Evidence `send a proposal and security-question list; proposal requested by September 1` means proposal due September 1 and security-question list due `To be confirmed`. The date does not apply to both deliverables.
- Evidence `SSO and data-retention review before a pilot` stays exactly `SSO and data-retention review before a pilot`. Do not expand it into SSO integration, SSO standards, policies, specifications, storage guidelines, documentation, or certifications.

Before returning the answer, silently reject and rewrite any sentence that fails one of these checks:

1. Each decision and commitment is explicit in the source.
2. Each date modifies the same item it modified in the source.
3. Each technical or security phrase preserves the source meaning and specificity.
4. Each unknown remains unknown and has no invented value or subcategory.
5. The draft claims no execution and ends with the required action-status receipt.

## Meeting preparation

1. Find the account, opportunity, attendees, recent meetings, correspondence, open commitments, product usage, and active risks that the requester may access.
2. State the meeting objective and the one outcome that most advances the deal.
3. Summarize each stakeholder's role, position, and unresolved concern.
4. Provide a recommended agenda, discovery questions, likely objections, proof points, and commitments to avoid making.
5. Finish with the next best commercial step and the evidence behind it.

## Post-meeting follow-up

1. Extract customer decisions, customer commitments, Risely commitments, dates, owners, objections, and unresolved questions from the latest meeting.
2. Compare them with the current CRM and previous commitments.
3. Draft a concise customer email in the sender's voice.
4. Prepare proposed CRM updates and internal tasks separately. If the current CRM value is unknown, list the field under unresolved unknowns and do not propose a replacement value.
5. When a proposal brief is requested, include only the verified customer request, verified prerequisites, customer-stated desired outcome, directly supported deadline, and the exact unresolved unknowns. Use `None evidenced` for any requested section without source evidence instead of inventing scope, proof, commercial inputs, or assumptions.
6. Return approval-ready proposals. Never send or write directly.
7. End every draft-only response with: `Action status: Draft only. No email was sent, no CRM record was changed, and no proposal was published.`

## Deal review

Return:

- Deal position
- Evidence-backed momentum
- Risks and missing stakeholders
- Commitments due
- Commercial gaps
- Recommended next action
- Draft customer communication when useful
- Sources and unresolved unknowns

## Approval boundary

Email sending, calendar invitations, CRM mutations, proposal publication, pricing, contracts, and external sharing require an explicit human approval through Command Center. If the approval tool is unavailable, return a draft only and state that no action occurred.
