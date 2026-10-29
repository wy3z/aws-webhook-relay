const assert = require("node:assert/strict");
const test = require("node:test");
const { buildSignature, getHeader, verifyRelaySignature } = require("../lambda/index");

const secret = "test-shared-secret";
const body = Buffer.from('{"EntityType":"Ticket","id":9101}');
const signed = (overrides = {}) => ({
  "X-Relay-Signature": buildSignature(body, secret),
  "X-Relay-Signature-Version": "v1",
  ...overrides,
});

test("a v1 HMAC-SHA256 of the raw body is accepted", () => {
  assert.equal(verifyRelaySignature(signed(), body, secret), true);
});

test("header names are case insensitive", () => {
  const headers = { "x-relay-signature": buildSignature(body, secret), "X-RELAY-SIGNATURE-VERSION": "v1" };
  assert.equal(verifyRelaySignature(headers, body, secret), true);
  assert.equal(getHeader({ "Content-Type": "text/plain" }, "content-type"), "text/plain");
});

test("wrong, missing or malformed signatures are rejected", () => {
  const valid = buildSignature(body, secret);
  for (const headers of [
    signed({ "X-Relay-Signature": buildSignature(body, "other-secret") }),
    signed({ "X-Relay-Signature": undefined }),
    signed({ "X-Relay-Signature": valid.toUpperCase() }),
    signed({ "X-Relay-Signature": valid.slice(1) }),
    signed({ "X-Relay-Signature": `sha256=${valid}` }),
  ]) {
    assert.equal(verifyRelaySignature(headers, body, secret), false);
  }
});

test("a missing or unknown signature version is rejected", () => {
  assert.equal(verifyRelaySignature(signed({ "X-Relay-Signature-Version": undefined }), body, secret), false);
  assert.equal(verifyRelaySignature(signed({ "X-Relay-Signature-Version": "v2" }), body, secret), false);
});

test("an empty shared secret never verifies", () => {
  const headers = signed({ "X-Relay-Signature": buildSignature(body, "") });
  assert.equal(verifyRelaySignature(headers, body, ""), false);
});

test("the signature covers exact bytes, so re-serialised JSON fails", () => {
  const reformatted = Buffer.from(JSON.stringify(JSON.parse(body), null, 2));
  assert.equal(verifyRelaySignature(signed(), reformatted, secret), false);
});
