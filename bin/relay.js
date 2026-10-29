#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const cdk = require("aws-cdk-lib");
const { WebhookRelayStack } = require("../lib/relay-stack");
const { validateRules } = require("../lambda/event-filter");

const app = new cdk.App();
const configPath = path.join(__dirname, "../config.json");
const fileConfig = fs.existsSync(configPath) ? JSON.parse(fs.readFileSync(configPath, "utf8")) : {};
const keys = [
  "account", "region", "vpcEnabled", "vpcId", "subnetIds", "availabilityZones",
  "securityGroupId", "createSecretsManagerEndpoint", "secretArn", "secretName",
  "primaryUrl", "secondaryUrl", "timeoutSeconds", "forwardTimeoutMs", "memorySize",
  "logRetentionDays", "rateLimit", "burstLimit", "filterRules", "filterTargets",
];
const config = {};
for (const key of keys) {
  const envKey = `RELAY_${key.replace(/[A-Z]/g, (letter) => `_${letter}`).toUpperCase()}`;
  const value = app.node.tryGetContext(key) ?? process.env[envKey] ?? fileConfig[key];
  if (value !== undefined && value !== "") config[key] = value;
}
for (const key of ["vpcEnabled", "createSecretsManagerEndpoint"]) {
  if (config[key] === "true") config[key] = true;
  if (config[key] === "false") config[key] = false;
}
for (const key of ["subnetIds", "availabilityZones", "filterTargets", "filterRules"]) {
  if (typeof config[key] === "string") config[key] = JSON.parse(config[key]);
}
const required = [
  "vpcEnabled", "timeoutSeconds", "forwardTimeoutMs", "memorySize",
  "logRetentionDays", "rateLimit", "burstLimit",
];
if (!config.secretArn && !config.secretName) required.push("primaryUrl");
if (config.vpcEnabled === true) {
  required.push("vpcId", "subnetIds", "availabilityZones", "securityGroupId", "createSecretsManagerEndpoint");
}
const missing = required.filter((key) => config[key] === undefined);
if (missing.length) throw new Error(`Missing relay config keys: ${missing.join(", ")}`);
if (typeof config.vpcEnabled !== "boolean") throw new Error("vpcEnabled must be true or false");
if (config.secretArn && config.secretName) throw new Error("Set only one of secretArn or secretName");
for (const key of ["timeoutSeconds", "forwardTimeoutMs", "memorySize", "logRetentionDays", "rateLimit", "burstLimit"]) {
  config[key] = Number(config[key]);
  if (!Number.isInteger(config[key]) || config[key] <= 0) throw new Error(`${key} must be a positive integer`);
}
if (config.timeoutSeconds > 29 || config.forwardTimeoutMs >= (config.timeoutSeconds - 2) * 1000) {
  throw new Error("timeoutSeconds must be <= 29; forwardTimeoutMs must leave more than two seconds for secret loading and response handling");
}
config.filterRules = validateRules(config.filterRules ?? {});
config.filterTargets = config.filterTargets ?? [];
if (!Array.isArray(config.filterTargets) || config.filterTargets.some((name) => !["primary", "secondary"].includes(name))) {
  throw new Error("filterTargets must be an array containing primary and/or secondary");
}
if (config.vpcEnabled) {
  for (const key of ["subnetIds", "availabilityZones"]) {
    if (!Array.isArray(config[key]) || !config[key].length || config[key].some((value) => typeof value !== "string" || !value.trim())) {
      throw new Error(`${key} must be a nonempty array of strings`);
    }
  }
  if (config.subnetIds.length !== config.availabilityZones.length) {
    throw new Error("subnetIds and availabilityZones must have matching lengths");
  }
  if (typeof config.createSecretsManagerEndpoint !== "boolean") {
    throw new Error("createSecretsManagerEndpoint must be true or false");
  }
}
for (const key of ["primaryUrl", "secondaryUrl"]) {
  if (!config[key]) continue;
  const url = new URL(config[key]);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error(`${key} must be an HTTP(S) URL without credentials`);
  }
}

new WebhookRelayStack(app, "WebhookRelayStack", {
  env: { account: config.account, region: config.region },
  config,
});
