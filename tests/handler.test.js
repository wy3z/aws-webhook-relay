const assert = require("node:assert/strict");
const test = require("node:test");

// Replace the AWS SDK before the handler loads it, so no test touches AWS.
let secretValue;
const sdkPath = require.resolve("@aws-sdk/client-secrets-manager");
require.cache[sdkPath] = {
  id: sdkPath, filename: sdkPath, loaded: true,
  exports: {
    GetSecretValueCommand: class { constructor(input) { this.input = input; } },
    SecretsManagerClient: class { async send() { return { SecretString: secretValue }; } },
  },
};
const { buildSignature, handler } = require("../lambda/index");

const sharedSecret = "test-shared-secret";
const baseSecret = {
  SharedSecret: sharedSecret,
  PRIMARY_URL: "https://primary.example.test/hook",
  PRIMARY_AUTH_TOKEN: "primary-token",
};
const ticketUpdate = '{"EntityType":"Ticket","Action":"Update","Fields":{"status":9003}}';
const assetUpdate = '{"EntityType":"Asset","Action":"Update","Fields":{"status":9003}}';
let calls;
let statuses;

test.beforeEach(() => {
  secretValue = JSON.stringify(baseSecret);
  calls = [];
  statuses = {};
  Object.assign(process.env, {
    RELAY_CONFIG_SECRET_NAME: "relay-test-secret",
    RELAY_TIMEOUT_MS: "1000",
    RELAY_FILTER_RULES: '{"entityTypes":["ticket"]}',
    RELAY_FILTER_TARGETS: '["secondary"]',
  });
  globalThis.fetch = async (url, options) => {
    calls.push({ url, ...options });
    return { ok: (statuses[url] ?? 200) < 300, status: statuses[url] ?? 200, body: null };
  };
  for (const method of ["info", "warn", "error"]) test.mock.method(console, method, () => {});
});

test.afterEach(() => test.mock.restoreAll());

function signedEvent(body, headers = {}) {
  return {
    httpMethod: "POST",
    requestContext: { requestId: "req-1" },
    headers: {
      "Content-Type": "application/json",
      "X-Relay-Signature": buildSignature(Buffer.from(body), sharedSecret),
      "X-Relay-Signature-Version": "v1",
      ...headers,
    },
    body,
  };
}

const withSecondary = (extra = {}) => JSON.stringify({
  ...baseSecret, SECONDARY_URL: "https://secondary.example.test/hook", ...extra,
});

test("only POST is accepted", async () => {
  const response = await handler({ ...signedEvent(ticketUpdate), httpMethod: "GET" });
  assert.equal(response.statusCode, 405);
});

test("an unusable secret fails closed with 500", async () => {
  secretValue = JSON.stringify({ PRIMARY_URL: baseSecret.PRIMARY_URL });
  assert.equal((await handler(signedEvent(ticketUpdate))).statusCode, 500);
  secretValue = JSON.stringify({ ...baseSecret, PRIMARY_URL: "https://user:pass@primary.example.test" });
  assert.equal((await handler(signedEvent(ticketUpdate))).statusCode, 500);
  assert.equal(calls.length, 0);
});

test("a bad signature returns 401 and forwards nothing", async () => {
  const response = await handler(signedEvent(ticketUpdate, { "X-Relay-Signature": "0".repeat(64) }));
  assert.equal(response.statusCode, 401);
  assert.equal(calls.length, 0);
});

test("a signed request is forwarded with only the documented headers", async () => {
  const response = await handler(signedEvent(ticketUpdate, {
    "X-Relay-Source": "upstream", "X-Autotask-Signature": "upstream-sig", Cookie: "session=1",
  }));
  assert.equal(response.statusCode, 202);
  assert.deepEqual(JSON.parse(response.body), { message: "Accepted", accepted: 1, targets: 1 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, baseSecret.PRIMARY_URL);
  assert.deepEqual(calls[0].headers, {
    "Content-Type": "application/json",
    "X-Relay-Verified": "true",
    "X-Relay-Source": "upstream",
    "X-Autotask-Signature": "upstream-sig",
    "X-Relay-Request-Id": "req-1",
    "X-Relay-Token": "primary-token",
  });
  assert.equal(calls[0].body.toString(), ticketUpdate);
});

test("a target without a token gets no X-Relay-Token", async () => {
  secretValue = JSON.stringify({ ...baseSecret, PRIMARY_AUTH_TOKEN: undefined });
  await handler(signedEvent(ticketUpdate));
  assert.equal("X-Relay-Token" in calls[0].headers, false);
});

test("the secondary target is skipped until it has a token", async () => {
  secretValue = withSecondary();
  await handler(signedEvent(ticketUpdate));
  assert.deepEqual(calls.map((call) => call.url), [baseSecret.PRIMARY_URL]);

  calls = [];
  secretValue = withSecondary({ SECONDARY_AUTH_TOKEN: "secondary-token" });
  await handler(signedEvent(ticketUpdate));
  assert.equal(calls.length, 2);
  assert.equal(calls[1].headers["X-Relay-Token"], "secondary-token");
});

test("a filtered secondary still returns 202 and reports it", async () => {
  secretValue = withSecondary({ SECONDARY_AUTH_TOKEN: "secondary-token" });
  const response = await handler(signedEvent(assetUpdate));
  assert.equal(response.statusCode, 202);
  assert.deepEqual(JSON.parse(response.body), { message: "Accepted", accepted: 1, targets: 1, filtered: 1 });
  assert.deepEqual(calls.map((call) => call.url), [baseSecret.PRIMARY_URL]);
});

test("one success out of two targets still returns 202", async () => {
  secretValue = withSecondary({ SECONDARY_AUTH_TOKEN: "secondary-token" });
  statuses["https://secondary.example.test/hook"] = 500;
  const response = await handler(signedEvent(ticketUpdate));
  assert.equal(response.statusCode, 202);
  assert.equal(JSON.parse(response.body).accepted, 1);
});

test("all targets failing returns 502", async () => {
  statuses[baseSecret.PRIMARY_URL] = 503;
  assert.equal((await handler(signedEvent(ticketUpdate))).statusCode, 502);
  globalThis.fetch = async () => { throw new Error("connection refused"); };
  assert.equal((await handler(signedEvent(ticketUpdate))).statusCode, 502);
});

test("a base64 body is verified and forwarded as the original bytes", async () => {
  const event = signedEvent(ticketUpdate);
  const response = await handler({ ...event, body: Buffer.from(ticketUpdate).toString("base64"), isBase64Encoded: true });
  assert.equal(response.statusCode, 202);
  assert.equal(calls[0].body.toString(), ticketUpdate);
});
