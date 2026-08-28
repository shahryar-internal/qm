import { OutboxEvent, PublicationEnvelope } from "../shared-contracts/index.mjs";

export function derivePublicationEnvelope(eventValue) {
  const event = OutboxEvent.validate(eventValue);
  return PublicationEnvelope.create({ outboxEvent: event });
}
