#!/usr/bin/env node

const fs = require("fs");
const { buildSignature } = require("../lambda/index");

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const paths = args.filter((arg) => arg !== "--dry-run");
  if (paths.length !== 1) throw new Error("Usage: node scripts/sign-and-send.js <fixture.json> [--dry-run]");
  const secret = process.env.RELAY_SHARED_SECRET;
  const url = process.env.RELAY_URL;
  if (!secret || !url) throw new Error("Set RELAY_SHARED_SECRET and RELAY_URL");
  const parsedUrl = new URL(url);
  if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) {
    throw new Error("RELAY_URL must be an HTTP(S) URL without credentials");
  }
  const body = fs.readFileSync(paths[0]);
  const headers = {
    "Content-Type": "application/json",
    "X-Relay-Signature": buildSignature(body, secret),
    "X-Relay-Signature-Version": "v1",
  };
  if (dryRun) {
    console.log(JSON.stringify(headers, null, 2));
    console.log(`curl -i -X POST ${Object.entries(headers).map(([key, value]) =>
      `-H ${shellQuote(`${key}: ${value}`)}`).join(" ")} --data-binary ${shellQuote(`@${paths[0]}`)} ${shellQuote(url)}`);
    return;
  }
  const response = await fetch(url, { method: "POST", headers, body, redirect: "error", signal: AbortSignal.timeout(30000) });
  console.log(`${response.status} ${await response.text()}`);
  if (!response.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
