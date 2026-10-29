function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeEntity(value) {
  return value.replace(/\s+/g, " ").trim().toLowerCase();
}

function validateRules(rules) {
  if (!isObject(rules)) throw new Error("Filter rules must be a JSON object");
  for (const [key, values] of Object.entries(rules)) {
    const numeric = ["alwaysForwardStatuses", "actionableStatuses"].includes(key);
    if (!numeric && !["entityTypes", "requireUpdateActionFor"].includes(key)) {
      throw new Error(`Unknown filter rule: ${key}`);
    }
    if (!Array.isArray(values) || values.some((value) => numeric
      ? typeof value !== "number" || !Number.isFinite(value)
      : typeof value !== "string" || !value.trim())) {
      throw new Error(`Invalid filter rule: ${key}`);
    }
  }
  return rules;
}

// Drop only understood payloads. Unknown shapes and change objects go downstream.
function eventDropReason(rawBody, rules = {}) {
  if (!Object.keys(rules).length) return null;
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (!isObject(payload) || payload.body != null) return null;

  const entity = payload.EntityType || payload.entityType || payload.entity ||
    payload.Entity || payload.resource;
  if (typeof entity !== "string" || !entity.trim()) return null;
  const entityType = normalizeEntity(entity);
  if (rules.entityTypes && !rules.entityTypes.map(normalizeEntity).includes(entityType)) {
    return "unsupported_entity_type";
  }
  if (!rules.alwaysForwardStatuses && !rules.actionableStatuses) return null;

  const fields = payload.Fields || payload.fields || payload.Changes ||
    payload.changes || payload.changedFields || payload.Change || payload.change;
  if (!isObject(fields)) return null;
  const statuses = Object.entries(fields)
    .filter(([key]) => key.toLowerCase().replace(/[^a-z0-9]/g, "") === "status")
    .map(([, value]) => value);
  statuses.push(...[payload.Status, payload.status].filter((value) => value != null));
  if (!statuses.length) return "no_status_field";
  if (statuses.some((value) =>
    !["string", "number"].includes(typeof value) ||
    String(value).trim() === "" || !Number.isFinite(Number(value))
  )) return null;

  const statusIds = statuses.map(Number);
  if (statusIds.some((id) => (rules.alwaysForwardStatuses || []).includes(id))) {
    return null;
  }
  if (!statusIds.some((id) => (rules.actionableStatuses || []).includes(id))) {
    return "status_not_actionable";
  }
  if (!rules.requireUpdateActionFor) return null;
  if (!rules.requireUpdateActionFor.map(normalizeEntity).includes(entityType)) {
    return "actionable_requires_update_entity";
  }
  const action = payload.Action || payload.action || payload.event || payload.Event;
  if (typeof action !== "string" || !action.trim()) return null;
  return action.trim().toLowerCase() === "update" ? null : "actionable_requires_update";
}

module.exports = { eventDropReason, validateRules };
