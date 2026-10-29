const crypto = require("crypto");
const { eventDropReason, validateRules } = require("./event-filter");

const SIGNATURE_HEADER = "X-Relay-Signature";
const VERSION_HEADER = "X-Relay-Signature-Version";
let secretsManagerClient;

function getHeader(headers = {}, name) {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === wanted) {
      return Array.isArray(value) ? value[0] : value == null ? undefined : String(value);
    }
  }
  return undefined;
}

function rawBodyFromEvent(event = {}) {
  if (event.body == null) return Buffer.alloc(0);
  if (event.isBase64Encoded) return Buffer.from(String(event.body), "base64");
  return Buffer.from(typeof event.body === "string" ? event.body : JSON.stringify(event.body));
}

function buildSignature(rawBody, sharedSecret) {
  return crypto.createHmac("sha256", sharedSecret).update(rawBody).digest("hex");
}

function timingSafeCompare(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function verifyRelaySignature(headers, rawBody, sharedSecret) {
  const signature = getHeader(headers, SIGNATURE_HEADER);
  return Boolean(sharedSecret && typeof signature === "string" &&
    /^[a-f0-9]{64}$/.test(signature) && getHeader(headers, VERSION_HEADER) === "v1" &&
    timingSafeCompare(signature, buildSignature(rawBody, sharedSecret)));
}

function jsonResponse(statusCode, payload) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  };
}

function buildForwardHeaders(event = {}, authToken) {
  const headers = {
    "Content-Type": getHeader(event.headers, "content-type") || "application/json",
    "X-Relay-Verified": "true",
  };
  const source = getHeader(event.headers, "x-relay-source");
  const originalSignature = getHeader(event.headers, "x-autotask-signature");
  const requestId = event.requestContext?.requestId || event.requestContext?.http?.requestId;
  if (source) headers["X-Relay-Source"] = source;
  if (originalSignature) headers["X-Autotask-Signature"] = originalSignature;
  if (requestId) headers["X-Relay-Request-Id"] = requestId;
  if (authToken) headers["X-Relay-Token"] = authToken;
  return headers;
}

async function loadSecretJson(secretName) {
  if (!secretName) throw new Error("RELAY_CONFIG_SECRET_NAME is not set");
  const { GetSecretValueCommand, SecretsManagerClient } = require("@aws-sdk/client-secrets-manager");
  if (!secretsManagerClient) secretsManagerClient = new SecretsManagerClient({});
  const response = await secretsManagerClient.send(new GetSecretValueCommand({ SecretId: secretName }));
  const secretString = response.SecretString || Buffer.from(response.SecretBinary || "").toString("utf8");
  return JSON.parse(secretString);
}

function validateConfig(config) {
  if (typeof config.SharedSecret !== "string" || !config.SharedSecret) {
    throw new Error("Relay config secret is missing SharedSecret");
  }
  if (!config.PRIMARY_URL) throw new Error("Relay config secret is missing PRIMARY_URL");
  for (const key of ["PRIMARY_URL", "SECONDARY_URL"]) {
    if (!config[key]) continue;
    const url = new URL(config[key]);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
      throw new Error(`Invalid ${key}`);
    }
  }
}

async function forwardToTarget(target, rawBody, event, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(target.url, {
      method: "POST",
      headers: buildForwardHeaders(event, target.authToken),
      body: rawBody,
      signal: controller.signal,
    });
    await response.body?.cancel();
    return { ok: response.ok, status: response.status };
  } finally {
    clearTimeout(timer);
  }
}

async function handler(event = {}) {
  const method = event.httpMethod || event.requestContext?.http?.method || "POST";
  if (method.toUpperCase() !== "POST") return jsonResponse(405, { message: "Method not allowed" });
  const rawBody = rawBodyFromEvent(event);
  const requestId = event.requestContext?.requestId || event.requestContext?.http?.requestId;
  let config, rules, filterTargets, timeoutMs;
  try {
    config = await loadSecretJson(process.env.RELAY_CONFIG_SECRET_NAME);
    validateConfig(config);
    rules = validateRules(JSON.parse(process.env.RELAY_FILTER_RULES || "{}"));
    filterTargets = JSON.parse(process.env.RELAY_FILTER_TARGETS || "[]");
    if (!Array.isArray(filterTargets) || filterTargets.some((name) => !["primary", "secondary"].includes(name))) {
      throw new Error("Invalid RELAY_FILTER_TARGETS");
    }
    timeoutMs = Number(process.env.RELAY_TIMEOUT_MS);
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("Invalid RELAY_TIMEOUT_MS");
  } catch {
    console.error("Failed to load relay config", { requestId });
    return jsonResponse(500, { message: "Relay config unavailable" });
  }
  if (!verifyRelaySignature(event.headers, rawBody, config.SharedSecret)) {
    console.warn("Rejected request with missing or invalid signature", { requestId });
    return jsonResponse(401, { message: "Invalid signature" });
  }

  let targets = [{ name: "primary", url: config.PRIMARY_URL.trim(), authToken: config.PRIMARY_AUTH_TOKEN }];
  if (config.SECONDARY_URL) {
    if (config.SECONDARY_AUTH_TOKEN) {
      targets.push({ name: "secondary", url: config.SECONDARY_URL.trim(), authToken: config.SECONDARY_AUTH_TOKEN });
    } else {
      console.error("Skipping secondary target because auth is not configured", { requestId });
    }
  }
  const dropReason = eventDropReason(rawBody, rules);
  let filtered = 0;
  targets = targets.filter((target) => {
    if (!dropReason || !filterTargets.includes(target.name)) return true;
    filtered += 1;
    console.info("Filtered relay event", { requestId, target: target.name, reason: dropReason });
    return false;
  });
  const results = await Promise.allSettled(
    targets.map((target) => forwardToTarget(target, rawBody, event, timeoutMs))
  );
  let accepted = 0;
  results.forEach((result, index) => {
    if (result.status === "fulfilled" && result.value.ok) {
      accepted += 1;
    } else {
      console.error("Failed to forward relay payload", {
        requestId,
        target: targets[index].name,
        ...(result.status === "fulfilled" ? { status: result.value.status } : { error: "Request failed" }),
      });
    }
  });

  // Any acceptance or deliberate filtering avoids retries that duplicate successful deliveries.
  if (accepted > 0 || filtered > 0) {
    return jsonResponse(202, {
      message: "Accepted", accepted, targets: targets.length,
      ...(filtered ? { filtered } : {}),
    });
  }
  return jsonResponse(502, { message: "Failed to reach relay target" });
}

module.exports = {
  buildForwardHeaders, buildSignature, getHeader, handler,
  rawBodyFromEvent, timingSafeCompare, verifyRelaySignature,
};
