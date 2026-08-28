import {
  InternalCalendarReadClient,
  InternalClarifyReadClient,
  InternalCommandCenterBrainReadClient,
  InternalGmailContextReadClient,
  InternalNotionReadClient,
} from "../../canary/connectors/providers.mjs";
import { createResolvedConnection } from "../../canary/connectors/types.mjs";

export const fixtureRecord = (provider, rootResourceRef, overrides = {}) => ({
  active: true,
  provider,
  connectionRef: "conn_12345678",
  principalRef: "usr_12345678",
  serverAccountRef: "srv_12345678",
  rootResourceRef,
  credentialLeaseRef: "lease_12345678",
  bindingNonce: "bind_1234567890abcdef",
  ...overrides,
});

export class FixtureResolver {
  constructor(resolver) {
    this.resolver = resolver;
    this.calls = [];
  }

  async resolve(request) {
    this.calls.push(request);
    return this.resolver(request);
  }
}

export class FakeHttpTransport {
  constructor(handler) {
    this.handler = handler;
    this.requests = [];
  }

  async execute(request) {
    this.requests.push(request);
    return this.handler(request);
  }
}

export class FakeMcpTransport {
  constructor(handler) {
    this.handler = handler;
    this.requests = [];
  }

  async invoke(request) {
    this.requests.push(request);
    return this.handler(request);
  }
}

export const openFixtureClient = (provider, rootResourceRef, transport, limits, overrides = {}) => {
  const connection = createResolvedConnection(fixtureRecord(provider, rootResourceRef, overrides));
  if (provider === "calendar") return new InternalCalendarReadClient(connection, transport, limits);
  if (provider === "gmail") return new InternalGmailContextReadClient(connection, transport, limits);
  if (provider === "clarify") return new InternalClarifyReadClient(connection, transport, limits);
  if (provider === "notion") return new InternalNotionReadClient(connection, transport, limits);
  return new InternalCommandCenterBrainReadClient(connection, transport, limits);
};
