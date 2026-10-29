const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { eventDropReason, validateRules } = require("../lambda/event-filter");

const root = path.join(__dirname, "..");
const exampleRules = JSON.parse(fs.readFileSync(path.join(root, "filter-rules.example.json"), "utf8"));
const fixture = (name) => fs.readFileSync(path.join(root, "fixtures", name));
const reason = (payload, rules = exampleRules) => eventDropReason(Buffer.from(JSON.stringify(payload)), rules);
const ticket = (fields, action = "Update") => ({ EntityType: "Ticket", Action: action, Fields: fields });

test("rules with unknown keys or wrong types are rejected", () => {
  assert.throws(() => validateRules([]), /JSON object/);
  assert.throws(() => validateRules({ statuses: [1] }), /Unknown filter rule/);
  assert.throws(() => validateRules({ actionableStatuses: ["9003"] }), /Invalid filter rule/);
  assert.throws(() => validateRules({ entityTypes: [" "] }), /Invalid filter rule/);
  assert.deepEqual(validateRules(exampleRules), exampleRules);
});

test("empty rules forward everything", () => {
  assert.equal(eventDropReason(fixture("non-ticket.json"), {}), null);
});

test("the example rules drop only the non-ticket fixture", () => {
  assert.equal(eventDropReason(fixture("non-ticket.json"), exampleRules), "unsupported_entity_type");
  for (const name of ["ticket-update.json", "ticket-note.json", "unknown-shape.json"]) {
    assert.equal(eventDropReason(fixture(name), exampleRules), null, name);
  }
});

test("payloads the filter can't read are forwarded", () => {
  assert.equal(eventDropReason(Buffer.from("not json"), exampleRules), null);
  assert.equal(reason([ticket({ status: 9005 })]), null);
  assert.equal(reason({ Action: "Update", Fields: { status: 9005 } }), null);
  assert.equal(reason({ EntityType: "Ticket", Action: "Update" }), null);
  assert.equal(reason(ticket({ status: { old: 9001, new: 9005 } })), null);
  assert.equal(reason(ticket({ status: "open" })), null);
});

test("a readable event with no status field is dropped", () => {
  assert.equal(reason(ticket({ queueID: 9201 })), "no_status_field");
});

test("status keys are matched after stripping punctuation, alongside a top-level status", () => {
  assert.equal(reason(ticket({ Status_: 9003 })), null);
  assert.equal(reason({ ...ticket({ queueID: 9201 }), status: 9005 }), "status_not_actionable");
});

test("an always-forward status wins over everything after it", () => {
  assert.equal(reason(ticket({ status: 9001 }, "Create")), null);
});

test("a status outside both lists is dropped", () => {
  assert.equal(reason(ticket({ status: 9005 })), "status_not_actionable");
});

test("actionable statuses need an update action on a listed entity", () => {
  assert.equal(reason(ticket({ status: 9003 })), null);
  assert.equal(reason(ticket({ status: 9003 }, "updated")), "actionable_requires_update");
  assert.equal(reason({ EntityType: "Ticket", Fields: { status: 9003 } }), null);
  assert.equal(
    reason({ EntityType: "TicketNote", Action: "Update", Fields: { status: 9003 } }),
    "actionable_requires_update_entity",
  );
});
