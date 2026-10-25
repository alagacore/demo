// End-to-end API tests against a real Postgres, connected as a non-superuser
// (like production) so row-level security is actually enforced.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import EmbeddedPostgres from "embedded-postgres";
import pg from "pg";

process.env.AUTH_TEST_MODE = "1";
const { makePool, migrate, withContext } = await import("../src/db.js");
const { setupAuth } = await import("../src/auth.js");
const { makeApp } = await import("../src/app.js");

let pgServer, pool, server, base;
// Postgres creates its own data folder (it runs as its own user when tests run as root).
const parent = fs.mkdtempSync(path.join(os.tmpdir(), "alaga-pg-"));
fs.chmodSync(parent, 0o777);
const dir = path.join(parent, "data");
const tok = (uid, email, verified) => `test:${uid}:${email}${verified ? ":verified" : ""}`;
async function call(method, url, { as, body } = {}) {
  const r = await fetch(base + url, { method, headers: { "content-type": "application/json", ...(as ? { authorization: `Bearer ${as}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null };
}

before(async () => {
  pgServer = new EmbeddedPostgres({ databaseDir: dir, user: "postgres", password: "pw", port: 54329, persistent: false, onLog: () => {}, onError: () => {} });
  await pgServer.initialise(); await pgServer.start();
  const admin = new pg.Client({ connectionString: "postgres://postgres:pw@localhost:54329/postgres" });
  await admin.connect();
  await admin.query("CREATE ROLE alaga_app LOGIN PASSWORD 'apppw' NOSUPERUSER NOBYPASSRLS");
  await admin.query("CREATE DATABASE alaga OWNER alaga_app");
  await admin.end();
  pool = makePool({ DATABASE_URL: "postgres://alaga_app:apppw@localhost:54329/alaga" });
  await migrate(pool);
  await migrate(pool); // running again does nothing
  setupAuth({ AUTH_TEST_MODE: "1" });
  server = makeApp({ pool, env: { ADMIN_EMAILS: "hello@alagacore.com" } }).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server?.close(); await pool?.end(); await pgServer?.stop(); fs.rmSync(parent, { recursive: true, force: true }); });

const OWNER_A = tok("uA", "tita@daycare.com"), OWNER_B = tok("uB", "other@daycare.com");
const PARENT = tok("uP", "maria@example.com"), STRANGER = tok("uS", "nobody@example.com");
const state = {};

test("daycares sign up and see only their own families", async () => {
  const a = await call("POST", "/providers", { as: OWNER_A, body: { name: "Tita's Family Child Care", city: "Culver City", capacity: 8 } });
  assert.equal(a.status, 201); state.A = a.body.id;
  const b = await call("POST", "/providers", { as: OWNER_B, body: { name: "Other Daycare" } });
  assert.equal(b.status, 201); state.B = b.body.id;
  assert.equal((await call("POST", "/providers", { as: OWNER_A, body: { name: "Second" } })).status, 409);

  const h = await call("POST", `/providers/${state.A}/households`, { as: OWNER_A, body: { name: "Reyes Family",
    guardians: [{ name: "Maria Reyes", relationship: "Mother", email: "Maria@Example.com" }, { name: "Daniel Reyes", relationship: "Father" }],
    children: [{ firstName: "Sofia", lastName: "Reyes", classroom: "prek" }, { firstName: "Mateo", lastName: "Reyes" }] } });
  assert.equal(h.status, 201);
  await call("POST", `/providers/${state.B}/households`, { as: OWNER_B, body: { name: "Kim Family", children: [{ firstName: "Jae" }] } });

  const famA = await call("GET", `/providers/${state.A}/families`, { as: OWNER_A });
  assert.equal(famA.status, 200);
  assert.deepEqual(famA.body.map((x) => x.name), ["Reyes Family"]);
  assert.equal(famA.body[0].children.length, 2);
  state.maria = famA.body[0].guardians.find((g) => g.name === "Maria Reyes");
  state.daniel = famA.body[0].guardians.find((g) => g.name === "Daniel Reyes");
  assert.equal(state.maria.email, "maria@example.com");

  assert.equal((await call("GET", `/providers/${state.A}/families`, { as: OWNER_B })).status, 403);
  assert.equal((await call("GET", `/providers/${state.A}/families`, { as: STRANGER })).status, 403);
  assert.equal((await call("GET", `/providers/${state.A}/families`)).status, 401);
});

test("the database itself hides other daycares' rows, even without a filter", async () => {
  const rows = await withContext(pool, { role: "owner", uid: "uB", providerId: state.B }, async (c) => (await c.query("SELECT name FROM households")).rows);
  assert.deepEqual(rows.map((r) => r.name), ["Kim Family"]);
  const none = await withContext(pool, { role: "", uid: "uS" }, async (c) => (await c.query("SELECT count(*)::int AS n FROM children")).rows[0].n);
  assert.equal(none, 0);
  await assert.rejects(withContext(pool, { role: "owner", uid: "uB", providerId: state.B }, (c) => c.query("INSERT INTO households (provider_id, name) VALUES ($1, 'Sneaky')", [state.A])));
});

test("invites: one use, right email only, and parents see only their family", async () => {
  assert.equal((await call("POST", `/providers/${state.A}/invites`, { as: OWNER_A, body: { guardianId: state.daniel.id } })).body.error, "email_required");
  assert.equal((await call("POST", `/providers/${state.A}/invites`, { as: OWNER_B, body: { guardianId: state.maria.id } })).status, 403);
  const inv = await call("POST", `/providers/${state.A}/invites`, { as: OWNER_A, body: { guardianId: state.maria.id } });
  assert.equal(inv.status, 201); assert.match(inv.body.code, /^[A-Z2-9]{8}$/);
  const code = inv.body.code;

  const stored = await withContext(pool, { role: "system" }, async (c) => (await c.query("SELECT code_hash FROM invites")).rows);
  assert.ok(stored.every((r) => r.code_hash !== code && r.code_hash.length === 64), "only a hash is stored");

  const pv = await call("POST", "/invites/preview", { body: { code: `${code.slice(0, 4)}-${code.slice(4)}` } });
  assert.equal(pv.status, 200); assert.equal(pv.body.provider, "Tita's Family Child Care"); assert.equal(pv.body.kidNames, "Mateo & Sofia");
  assert.equal((await call("POST", "/invites/preview", { body: { code: "AAAABBBB" } })).status, 404);

  assert.equal((await call("POST", "/invites/redeem", { as: STRANGER, body: { code } })).body.error, "email_mismatch");
  assert.equal((await call("POST", "/invites/redeem", { as: OWNER_B, body: { code } })).status, 403);
  const ok = await call("POST", "/invites/redeem", { as: PARENT, body: { code } });
  assert.equal(ok.status, 200);
  assert.equal((await call("POST", "/invites/redeem", { as: PARENT, body: { code } })).body.error, "accepted");

  const fam = await call("GET", "/parent/family", { as: PARENT });
  assert.equal(fam.status, 200);
  assert.deepEqual(fam.body.children.map((k) => k.first_name), ["Mateo", "Sofia"]);
  assert.equal(fam.body.guardians.length, 2);
  assert.equal(fam.body.provider.name, "Tita's Family Child Care");
  assert.equal((await call("GET", `/providers/${state.A}/families`, { as: PARENT })).status, 403);
  assert.equal((await call("GET", "/parent/family", { as: STRANGER })).status, 404);
  assert.equal((await call("POST", "/providers", { as: PARENT, body: { name: "x" } })).body.error, "family_account");

  // parents get child details, minus the provider's private notes
  await call("PATCH", `/providers/${state.A}/children/${fam.body.children[0].id}`, { as: OWNER_A, body: { details: { copay: 120, notes: "private note" } } });
  const fam2 = await call("GET", "/parent/family", { as: PARENT });
  assert.equal(fam2.body.children[0].details.copay, 120);
  assert.equal(fam2.body.children[0].details.notes, undefined);
  const g3 = await call("POST", `/providers/${state.A}/households/${fam.body.household.id}/guardians`, { as: OWNER_A, body: { name: "Elena Reyes", relationship: "Grandmother" } });
  assert.equal(g3.status, 201);
  assert.equal((await call("POST", `/providers/${state.B}/households/${fam.body.household.id}/guardians`, { as: OWNER_B, body: { name: "x" } })).status, 404);
  const me = await call("GET", "/me", { as: PARENT });
  assert.equal(me.body.guardianOf.length, 1); assert.equal(me.body.memberships.length, 0);
  const famView = await call("GET", `/providers/${state.A}/families`, { as: OWNER_A });
  assert.equal(famView.body[0].guardians.find((g) => g.id === state.maria.id).has_access, true);
});

test("cancelled and expired invites don't work; access can be removed", async () => {
  await call("POST", `/providers/${state.A}/guardians/${state.daniel.id}`, { as: OWNER_A });
  await call("PATCH", `/providers/${state.A}/guardians/${state.daniel.id}`, { as: OWNER_A, body: { email: "daniel@example.com" } });
  const a = await call("POST", `/providers/${state.A}/invites`, { as: OWNER_A, body: { guardianId: state.daniel.id } });
  const b = await call("POST", `/providers/${state.A}/invites`, { as: OWNER_A, body: { guardianId: state.daniel.id } });
  assert.equal((await call("POST", "/invites/preview", { body: { code: a.body.code } })).body.state, "revoked", "a new code cancels the old one");
  assert.equal((await call("DELETE", `/providers/${state.A}/invites/${b.body.id}`, { as: OWNER_A })).status, 204);
  assert.equal((await call("POST", "/invites/preview", { body: { code: b.body.code } })).body.state, "revoked");
  const c = await call("POST", `/providers/${state.A}/invites`, { as: OWNER_A, body: { guardianId: state.daniel.id } });
  await withContext(pool, { role: "system" }, (cl) => cl.query("UPDATE invites SET expires_at = now() - interval '1 minute' WHERE id = $1", [c.body.id]));
  assert.equal((await call("POST", "/invites/preview", { body: { code: c.body.code } })).body.state, "expired");

  assert.equal((await call("DELETE", `/providers/${state.A}/guardians/${state.maria.id}/access`, { as: OWNER_A })).status, 204);
  assert.equal((await call("GET", "/parent/family", { as: PARENT })).status, 404);
});

test("audit log records access and can't be edited", async () => {
  const n = await withContext(pool, { role: "owner", uid: "uA", providerId: state.A }, async (c) => (await c.query("SELECT count(*)::int AS n FROM audit_log")).rows[0].n);
  assert.ok(n >= 5);
  // No delete/update permission exists: nothing is removed or changed.
  const del = await withContext(pool, { role: "system" }, (c) => c.query("DELETE FROM audit_log"));
  assert.equal(del.rowCount, 0);
  const upd = await withContext(pool, { role: "owner", uid: "uA", providerId: state.A }, (c) => c.query("UPDATE audit_log SET action = 'x'"));
  assert.equal(upd.rowCount, 0);
  const after = await withContext(pool, { role: "owner", uid: "uA", providerId: state.A }, async (c) => (await c.query("SELECT count(*)::int AS n FROM audit_log")).rows[0].n);
  assert.ok(after >= n);
});

test("team view needs a verified team email", async () => {
  assert.equal((await call("GET", "/admin/providers", { as: tok("uT", "hello@alagacore.com") })).status, 403);
  const r = await call("GET", "/admin/providers", { as: tok("uT", "hello@alagacore.com", true) });
  assert.equal(r.status, 200); assert.equal(r.body.length, 2);
  assert.equal((await call("GET", "/admin/providers", { as: OWNER_A })).status, 403);
});

test("invite guessing is rate limited", async () => {
  let last;
  for (let i = 0; i < 12; i++) last = await call("POST", "/invites/preview", { body: { code: "ZZZZZZZZ" } });
  assert.equal(last.status, 429);
});
