// Alaga API: daycare accounts, families, and parent invites.
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import { withContext } from "./db.js";
import { requireUser, optionalUser } from "./auth.js";

const INVITE_DAYS = 7;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const hashCode = (code) => crypto.createHash("sha256").update(`alaga-invite:${code}`).digest("hex");
const hashBeta = (code) => crypto.createHash("sha256").update(`alaga-beta:${code}`).digest("hex");
const normCode = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
function newCode() {
  const bytes = crypto.randomBytes(8);
  return Array.from(bytes, (b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
}
const str = (v, max = 200) => (v == null ? null : String(v).trim().slice(0, max) || null);
const isUuid = (v) => /^[0-9a-f-]{36}$/i.test(String(v || ""));
const isEmail = (v) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(v || ""));
const dateOrNull = (v) => (v && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null);
// Child details a parent never sees (the provider's private notes and flags).
const PRIVATE_DETAIL_KEYS = ["notes", "notices", "fromTourId", "custodyNotes", "providerNotes", "accessLog"];
const forParent = (details) => Object.fromEntries(Object.entries(details || {}).filter(([k]) => !PRIVATE_DETAIL_KEYS.includes(k)));

class HttpError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }

export function makeApp({ pool, env = process.env }) {
  const app = express();
  const admins = String(env.ADMIN_EMAILS || "hello@alagacore.com").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
  const origins = String(env.ALLOWED_ORIGINS || "https://alaga-master-8426.vercel.app,http://localhost:5173,http://localhost:4173").split(",").map((s) => s.trim());

  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes(o)), allowedHeaders: ["Authorization", "Content-Type"], methods: ["GET", "POST", "PATCH", "DELETE"] }));
  app.use(express.json({ limit: "100kb" }));
  app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));
  const betaRequired = env.BETA_REQUIRED !== "0";
  const isTeam = (req) => !!(req.user && req.user.emailVerified && admins.includes(req.user.email));
  const requireTeam = (req, res, next) => (isTeam(req) ? next() : res.status(403).json({ error: "no_access" }));
  const feedbackLimiter = rateLimit({ windowMs: 60 * 60_000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: "too_many_tries" } });
  // Separate limits for guessing invite codes, beta codes and demo links.
  const guessLimiter = () => rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "too_many_tries" } });
  const inviteLimiter = guessLimiter(), betaLimiter = guessLimiter(), demoLimiter = guessLimiter();

  const audit = (client, req, providerId, action, target, meta = {}) =>
    client.query("INSERT INTO audit_log (provider_id, actor_uid, action, target, meta, ip) VALUES ($1,$2,$3,$4,$5,$6)",
      [providerId || null, req.user?.uid || null, action, target || null, meta, req.ip]);

  // The daycare this request is for, and the user's role there (checked
  // against memberships, never taken from the request).
  async function staffContext(req, roles = ["owner", "staff"]) {
    const pid = req.params.pid;
    if (!isUuid(pid)) throw new HttpError(404, "not_found");
    const role = await withContext(pool, { role: "", uid: req.user.uid }, async (c) => {
      const r = await c.query("SELECT role FROM memberships WHERE user_uid = $1 AND provider_id = $2", [req.user.uid, pid]);
      return r.rows[0]?.role;
    });
    if (!role || !roles.includes(role)) throw new HttpError(403, "no_access");
    return { role, uid: req.user.uid, providerId: pid };
  }
  const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
    if (e instanceof HttpError) return res.status(e.status).json({ error: e.code });
    console.error(e);
    res.status(500).json({ error: "server_error" });
  });

  app.get("/health", (req, res) => res.json({ ok: true }));

  // Who am I: the daycares I work at, and the families I belong to.
  app.get("/me", requireUser, wrap(async (req, res) => {
    const out = await withContext(pool, { role: "", uid: req.user.uid }, async (c) => {
      const m = await c.query("SELECT provider_id, role FROM memberships WHERE user_uid = $1", [req.user.uid]);
      const g = await c.query("SELECT id, provider_id, household_id, name FROM guardians WHERE user_uid = $1", [req.user.uid]);
      return { memberships: m.rows, guardianOf: g.rows };
    });
    // Names need each daycare's own context.
    for (const m of out.memberships) {
      m.provider = await withContext(pool, { role: m.role, uid: req.user.uid, providerId: m.provider_id }, async (c) => (await c.query("SELECT name FROM providers WHERE id = $1", [m.provider_id])).rows[0]?.name);
    }
    for (const g of out.guardianOf) {
      g.provider = await withContext(pool, { role: "parent", uid: req.user.uid, providerId: g.provider_id, householdId: g.household_id }, async (c) => (await c.query("SELECT name FROM providers WHERE id = $1", [g.provider_id])).rows[0]?.name);
    }
    res.json({ uid: req.user.uid, email: req.user.email, isTeam: req.user.emailVerified && admins.includes(req.user.email), ...out });
  }));

  // A new daycare (end of the setup wizard). One per account for now.
  app.post("/providers", requireUser, wrap(async (req, res) => {
    const b = req.body || {};
    const name = str(b.name);
    if (!name) throw new HttpError(400, "name_required");
    const out = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      if ((await c.query("SELECT 1 FROM guardians WHERE user_uid = $1", [req.user.uid])).rowCount) throw new HttpError(409, "family_account");
      if ((await c.query("SELECT 1 FROM memberships WHERE user_uid = $1", [req.user.uid])).rowCount) throw new HttpError(409, "already_has_daycare");
      // Private beta: a valid code is used up as the daycare is created.
      let betaId = null;
      if (betaRequired && !isTeam(req)) {
        const code = normCode(b.betaCode);
        if (!code) throw new HttpError(403, "beta_code_required");
        const r = await c.query("UPDATE beta_codes SET uses = uses + 1 WHERE code_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AND uses < max_uses RETURNING id", [hashBeta(code)]);
        if (!r.rowCount) throw new HttpError(403, "beta_code_invalid");
        betaId = r.rows[0].id;
      }
      const p = await c.query(
        "INSERT INTO providers (name, city, license, provider_type, capacity, settings) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, city, license, provider_type, capacity, settings",
        [name, str(b.city), str(b.license), str(b.providerType), Number.isFinite(+b.capacity) ? Math.max(0, Math.min(500, +b.capacity)) : null, b.settings && typeof b.settings === "object" ? b.settings : {}],
      );
      await c.query("INSERT INTO memberships (provider_id, user_uid, email, role) VALUES ($1,$2,$3,'owner')", [p.rows[0].id, req.user.uid, req.user.email]);
      if (betaId) await c.query("INSERT INTO beta_code_uses (beta_code_id, provider_id, user_uid) VALUES ($1,$2,$3)", [betaId, p.rows[0].id, req.user.uid]);
      await audit(c, req, p.rows[0].id, "provider.create", p.rows[0].id);
      return p.rows[0];
    });
    res.status(201).json(out);
  }));

  app.get("/providers/:pid", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    const p = await withContext(pool, ctx, async (c) => (await c.query("SELECT id, name, city, license, provider_type, capacity, settings FROM providers WHERE id = $1", [ctx.providerId])).rows[0]);
    res.json({ ...p, role: ctx.role });
  }));

  app.patch("/providers/:pid", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req, ["owner"]);
    const b = req.body || {};
    const p = await withContext(pool, ctx, async (c) => {
      const r = await c.query(
        `UPDATE providers SET name = coalesce($2, name), city = coalesce($3, city), license = coalesce($4, license),
           capacity = coalesce($5, capacity), settings = CASE WHEN $6::jsonb IS NULL THEN settings ELSE settings || $6::jsonb END
         WHERE id = $1 RETURNING id, name, city, license, provider_type, capacity, settings`,
        [ctx.providerId, str(b.name), str(b.city), str(b.license), Number.isFinite(+b.capacity) ? +b.capacity : null, b.settings && typeof b.settings === "object" ? JSON.stringify(b.settings) : null],
      );
      await audit(c, req, ctx.providerId, "provider.update", ctx.providerId, { fields: Object.keys(b) });
      return r.rows[0];
    });
    res.json(p);
  }));

  // All families at the daycare, with guardians (and whether each has app
  // access) and children.
  app.get("/providers/:pid/families", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    const out = await withContext(pool, ctx, async (c) => {
      const h = (await c.query("SELECT id, name FROM households ORDER BY name")).rows;
      const g = (await c.query("SELECT id, household_id, name, relationship, email, phone, (user_uid IS NOT NULL) AS has_access, linked_at FROM guardians ORDER BY created_at")).rows;
      const k = (await c.query("SELECT id, household_id, first_name, last_name, birth_date, classroom, enroll_date, status, details FROM children ORDER BY first_name")).rows;
      const inv = (await c.query("SELECT DISTINCT ON (guardian_id) id, guardian_id, expires_at, used_at, revoked_at FROM invites ORDER BY guardian_id, created_at DESC")).rows;
      await audit(c, req, ctx.providerId, "families.view", null);
      return h.map((x) => ({
        ...x,
        guardians: g.filter((y) => y.household_id === x.id).map((y) => ({ ...y, invite: inviteState(inv.find((z) => z.guardian_id === y.id)) })),
        children: k.filter((y) => y.household_id === x.id),
      }));
    });
    res.json(out);
  }));

  app.post("/providers/:pid/households", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    const b = req.body || {};
    const name = str(b.name);
    if (!name) throw new HttpError(400, "name_required");
    const out = await withContext(pool, ctx, async (c) => {
      const h = (await c.query("INSERT INTO households (provider_id, name) VALUES ($1,$2) RETURNING id, name", [ctx.providerId, name])).rows[0];
      for (const g of (Array.isArray(b.guardians) ? b.guardians : []).slice(0, 6)) {
        if (!str(g.name)) continue;
        if (g.email && !isEmail(g.email)) throw new HttpError(400, "bad_email");
        await c.query("INSERT INTO guardians (provider_id, household_id, name, relationship, email, phone) VALUES ($1,$2,$3,$4,$5,$6)", [ctx.providerId, h.id, str(g.name), str(g.relationship, 60), g.email ? String(g.email).trim().toLowerCase() : null, str(g.phone, 40)]);
      }
      for (const k of (Array.isArray(b.children) ? b.children : []).slice(0, 12)) {
        if (!str(k.firstName, 100)) continue;
        await c.query("INSERT INTO children (provider_id, household_id, first_name, last_name, birth_date, classroom, enroll_date, status, details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
          [ctx.providerId, h.id, str(k.firstName, 100), str(k.lastName, 100), dateOrNull(k.birthDate), str(k.classroom, 40), dateOrNull(k.enrollDate), ["pending", "active", "withdrawn"].includes(k.status) ? k.status : "active", k.details && typeof k.details === "object" ? k.details : {}]);
      }
      await audit(c, req, ctx.providerId, "household.create", h.id);
      return h;
    });
    res.status(201).json(out);
  }));

  app.post("/providers/:pid/households/:hid/guardians", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    if (!isUuid(req.params.hid)) throw new HttpError(404, "not_found");
    const b = req.body || {};
    if (!str(b.name)) throw new HttpError(400, "name_required");
    if (b.email && !isEmail(b.email)) throw new HttpError(400, "bad_email");
    const out = await withContext(pool, ctx, async (c) => {
      if (!(await c.query("SELECT 1 FROM households WHERE id = $1", [req.params.hid])).rowCount) throw new HttpError(404, "not_found");
      const r = await c.query("INSERT INTO guardians (provider_id, household_id, name, relationship, email, phone) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, relationship, email, phone",
        [ctx.providerId, req.params.hid, str(b.name), str(b.relationship, 60), b.email ? String(b.email).trim().toLowerCase() : null, str(b.phone, 40)]);
      await audit(c, req, ctx.providerId, "guardian.create", r.rows[0].id);
      return r.rows[0];
    });
    res.status(201).json(out);
  }));

  app.patch("/providers/:pid/guardians/:gid", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    if (!isUuid(req.params.gid)) throw new HttpError(404, "not_found");
    const b = req.body || {};
    if (b.email && !isEmail(b.email)) throw new HttpError(400, "bad_email");
    const out = await withContext(pool, ctx, async (c) => {
      const r = await c.query("UPDATE guardians SET name = coalesce($2, name), relationship = coalesce($3, relationship), email = coalesce($4, email), phone = coalesce($5, phone) WHERE id = $1 RETURNING id, name, relationship, email, phone",
        [req.params.gid, str(b.name), str(b.relationship, 60), b.email ? String(b.email).trim().toLowerCase() : null, str(b.phone, 40)]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, ctx.providerId, "guardian.update", req.params.gid, { fields: Object.keys(b) });
      return r.rows[0];
    });
    res.json(out);
  }));

  app.patch("/providers/:pid/children/:cid", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    if (!isUuid(req.params.cid)) throw new HttpError(404, "not_found");
    const b = req.body || {};
    const out = await withContext(pool, ctx, async (c) => {
      const r = await c.query(
        `UPDATE children SET first_name = coalesce($2, first_name), last_name = coalesce($3, last_name), birth_date = coalesce($4, birth_date),
           classroom = coalesce($5, classroom), enroll_date = coalesce($6, enroll_date), status = coalesce($7, status),
           details = CASE WHEN $8::jsonb IS NULL THEN details ELSE details || $8::jsonb END
         WHERE id = $1 RETURNING id, household_id, first_name, last_name, birth_date, classroom, enroll_date, status, details`,
        [req.params.cid, str(b.firstName, 100), str(b.lastName, 100), dateOrNull(b.birthDate), str(b.classroom, 40), dateOrNull(b.enrollDate), ["pending", "active", "withdrawn"].includes(b.status) ? b.status : null, b.details && typeof b.details === "object" ? JSON.stringify(b.details) : null]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, ctx.providerId, "child.update", req.params.cid, { fields: Object.keys(b) });
      return r.rows[0];
    });
    res.json(out);
  }));

  // Invite a guardian to the family app. The code is returned once; only its
  // hash is stored. Any earlier pending invite for that guardian is cancelled.
  app.post("/providers/:pid/invites", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    const gid = req.body?.guardianId;
    if (!isUuid(gid)) throw new HttpError(400, "guardian_required");
    const code = newCode();
    const out = await withContext(pool, ctx, async (c) => {
      const g = (await c.query("SELECT id, household_id, email, user_uid FROM guardians WHERE id = $1", [gid])).rows[0];
      if (!g) throw new HttpError(404, "not_found");
      if (!g.email) throw new HttpError(400, "email_required");
      if (g.user_uid) throw new HttpError(409, "already_has_access");
      await c.query("UPDATE invites SET revoked_at = now() WHERE guardian_id = $1 AND used_at IS NULL AND revoked_at IS NULL", [gid]);
      const r = await c.query("INSERT INTO invites (provider_id, household_id, guardian_id, email, code_hash, expires_at, created_by_uid) VALUES ($1,$2,$3,$4,$5, now() + ($6 || ' days')::interval, $7) RETURNING id, expires_at",
        [ctx.providerId, g.household_id, gid, g.email, hashCode(code), String(INVITE_DAYS), req.user.uid]);
      await audit(c, req, ctx.providerId, "invite.create", gid);
      return { id: r.rows[0].id, code, email: g.email, expiresAt: r.rows[0].expires_at };
    });
    res.status(201).json(out);
  }));

  app.delete("/providers/:pid/invites/:iid", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    if (!isUuid(req.params.iid)) throw new HttpError(404, "not_found");
    await withContext(pool, ctx, async (c) => {
      const r = await c.query("UPDATE invites SET revoked_at = now() WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL", [req.params.iid]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, ctx.providerId, "invite.revoke", req.params.iid);
    });
    res.status(204).end();
  }));

  app.delete("/providers/:pid/guardians/:gid/access", requireUser, wrap(async (req, res) => {
    const ctx = await staffContext(req);
    if (!isUuid(req.params.gid)) throw new HttpError(404, "not_found");
    await withContext(pool, ctx, async (c) => {
      const r = await c.query("UPDATE guardians SET user_uid = NULL, linked_at = NULL WHERE id = $1", [req.params.gid]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, ctx.providerId, "guardian.remove_access", req.params.gid);
    });
    res.status(204).end();
  }));

  // Parent side. Preview tells the code holder who invited them (no sign-in
  // yet); redeem links their signed-in account. Both are rate limited.
  async function findInvite(c, rawCode) {
    const code = normCode(rawCode);
    if (code.length !== 8) return { state: "invalid" };
    const inv = (await c.query("SELECT * FROM invites WHERE code_hash = $1", [hashCode(code)])).rows[0];
    if (!inv) return { state: "invalid" };
    const st = inviteState(inv).status;
    return { state: st === "pending" ? "ok" : st, inv };
  }
  app.post("/invites/preview", inviteLimiter, wrap(async (req, res) => {
    const out = await withContext(pool, { role: "system" }, async (c) => {
      const { state, inv } = await findInvite(c, req.body?.code);
      if (state !== "ok") return { state };
      const p = (await c.query("SELECT name FROM providers WHERE id = $1", [inv.provider_id])).rows[0];
      const g = (await c.query("SELECT name FROM guardians WHERE id = $1", [inv.guardian_id])).rows[0];
      const kids = (await c.query("SELECT first_name FROM children WHERE household_id = $1 AND status <> 'withdrawn' ORDER BY first_name", [inv.household_id])).rows.map((r) => r.first_name);
      return { state, provider: p?.name, guardianName: g?.name, kidNames: kids.join(" & "), email: inv.email };
    });
    res.status(out.state === "ok" ? 200 : 404).json(out);
  }));

  app.post("/invites/redeem", inviteLimiter, requireUser, wrap(async (req, res) => {
    const out = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const { state, inv } = await findInvite(c, req.body?.code);
      if (state !== "ok") throw new HttpError(404, state);
      if (inv.email.toLowerCase() !== req.user.email) throw new HttpError(403, "email_mismatch");
      if ((await c.query("SELECT 1 FROM memberships WHERE user_uid = $1", [req.user.uid])).rowCount) throw new HttpError(409, "daycare_account");
      // Lock the invite row so two tabs can't both use it.
      const locked = await c.query("UPDATE invites SET used_at = now(), used_by_uid = $2 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING id", [inv.id, req.user.uid]);
      if (!locked.rowCount) throw new HttpError(409, "used");
      await c.query("UPDATE guardians SET user_uid = $2, linked_at = now() WHERE id = $1", [inv.guardian_id, req.user.uid]);
      await audit(c, req, inv.provider_id, "invite.redeem", inv.guardian_id);
      return { providerId: inv.provider_id, householdId: inv.household_id, guardianId: inv.guardian_id };
    });
    res.json(out);
  }));

  // A parent's own family: children and the other guardians' names.
  app.get("/parent/family", requireUser, wrap(async (req, res) => {
    const me = await withContext(pool, { role: "", uid: req.user.uid }, async (c) => (await c.query("SELECT id, provider_id, household_id, name FROM guardians WHERE user_uid = $1", [req.user.uid])).rows);
    if (!me.length) throw new HttpError(404, "no_family");
    const pick = me.find((g) => g.household_id === req.query.household) || me[0];
    const ctx = { role: "parent", uid: req.user.uid, providerId: pick.provider_id, householdId: pick.household_id };
    const out = await withContext(pool, ctx, async (c) => {
      const p = (await c.query("SELECT id, name, city FROM providers WHERE id = $1", [pick.provider_id])).rows[0];
      const h = (await c.query("SELECT id, name FROM households WHERE id = $1", [pick.household_id])).rows[0];
      const g = (await c.query("SELECT id, name, relationship FROM guardians WHERE household_id = $1", [pick.household_id])).rows;
      const k = (await c.query("SELECT id, first_name, last_name, birth_date, classroom, enroll_date, status, details FROM children WHERE household_id = $1 AND status <> 'withdrawn' ORDER BY first_name", [pick.household_id])).rows
        .map((x) => ({ ...x, details: forParent(x.details) }));
      await audit(c, req, pick.provider_id, "parent.family_view", pick.household_id);
      return { provider: p, household: h, me: { id: pick.id, name: pick.name }, guardians: g, children: k };
    });
    res.json(out);
  }));

  // Private beta: check a code before creating an account (doesn't use it).
  app.post("/beta/check", betaLimiter, wrap(async (req, res) => {
    const code = normCode(req.body?.code);
    const ok = code.length >= 6 && await withContext(pool, { role: "system" }, async (c) =>
      (await c.query("SELECT 1 FROM beta_codes WHERE code_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AND uses < max_uses", [hashBeta(code)])).rowCount > 0);
    res.status(ok ? 200 : 404).json({ ok: !!ok, required: betaRequired });
  }));

  // Private demo links open the sample daycare (sample data only).
  app.post("/demo/check", demoLimiter, wrap(async (req, res) => {
    const token = String(req.body?.token || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
    const row = token.length >= 12 && await withContext(pool, { role: "system" }, async (c) =>
      (await c.query("UPDATE demo_links SET views = views + 1 WHERE token = $1 AND active AND (expires_at IS NULL OR expires_at > now()) RETURNING id, label", [token])).rows[0]);
    if (!row) return res.status(404).json({ ok: false });
    res.json({ ok: true });
  }));

  // Feedback and post-demo surveys. Signed-in users are recorded with it.
  app.post("/feedback", feedbackLimiter, optionalUser, wrap(async (req, res) => {
    const b = req.body || {};
    const kind = b.kind === "demo_survey" ? "demo_survey" : "feedback";
    const rating = Number.isInteger(b.rating) && b.rating >= 1 && b.rating <= 5 ? b.rating : null;
    const message = str(b.message, 4000);
    const answers = b.answers && typeof b.answers === "object" && !Array.isArray(b.answers) ? JSON.parse(JSON.stringify(b.answers).slice(0, 4000)) : {};
    if (!rating && !message && !Object.keys(answers).length) throw new HttpError(400, "empty");
    await withContext(pool, { role: "system", uid: req.user?.uid }, async (c) => {
      let providerId = null, demoId = null;
      if (req.user) providerId = (await c.query("SELECT provider_id FROM memberships WHERE user_uid = $1 LIMIT 1", [req.user.uid])).rows[0]?.provider_id
        || (await c.query("SELECT provider_id FROM guardians WHERE user_uid = $1 LIMIT 1", [req.user.uid])).rows[0]?.provider_id || null;
      if (b.demoToken) demoId = (await c.query("SELECT id FROM demo_links WHERE token = $1", [String(b.demoToken).slice(0, 64)])).rows[0]?.id || null;
      await c.query("INSERT INTO feedback (kind, rating, message, answers, contact, screen, role, user_uid, user_email, provider_id, demo_link_id, language) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        [kind, rating, message, answers, str(b.contact, 200), str(b.screen, 80), str(b.role, 20), req.user?.uid || null, req.user?.email || null, providerId, demoId, str(b.language, 20)]);
    });
    res.status(201).json({ ok: true });
  }));

  // Alaga team tools ---------------------------------------------------------
  app.get("/admin/beta-codes", requireUser, requireTeam, wrap(async (req, res) => {
    res.json(await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => (await c.query(
      `SELECT b.id, b.label, b.max_uses, b.uses, b.expires_at, b.revoked_at, b.created_at,
         coalesce((SELECT json_agg(json_build_object('provider', p.name, 'used_at', u.used_at) ORDER BY u.used_at) FROM beta_code_uses u LEFT JOIN providers p ON p.id = u.provider_id WHERE u.beta_code_id = b.id), '[]') AS used_by
       FROM beta_codes b ORDER BY b.created_at DESC`)).rows));
  }));
  app.post("/admin/beta-codes", requireUser, requireTeam, wrap(async (req, res) => {
    const b = req.body || {};
    const label = str(b.label) || "Beta code";
    const maxUses = Math.max(1, Math.min(1000, parseInt(b.maxUses, 10) || 1));
    const days = Math.max(0, Math.min(365, parseInt(b.expiresInDays, 10) || 0));
    const code = newCode();
    const row = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const r = await c.query("INSERT INTO beta_codes (code_hash, label, max_uses, expires_at, created_by) VALUES ($1,$2,$3, CASE WHEN $4::int > 0 THEN now() + ($4 || ' days')::interval ELSE NULL END, $5) RETURNING id, label, max_uses, expires_at",
        [hashBeta(code), label, maxUses, days, req.user.email]);
      await audit(c, req, null, "admin.beta_code_create", r.rows[0].id);
      return r.rows[0];
    });
    res.status(201).json({ ...row, code });
  }));
  app.delete("/admin/beta-codes/:id", requireUser, requireTeam, wrap(async (req, res) => {
    if (!isUuid(req.params.id)) throw new HttpError(404, "not_found");
    await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const r = await c.query("UPDATE beta_codes SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", [req.params.id]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, null, "admin.beta_code_revoke", req.params.id);
    });
    res.status(204).end();
  }));
  app.get("/admin/demo-links", requireUser, requireTeam, wrap(async (req, res) => {
    res.json(await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => (await c.query(
      "SELECT d.id, d.token, d.label, d.active, d.views, d.expires_at, d.created_at, (SELECT count(*)::int FROM feedback f WHERE f.demo_link_id = d.id) AS surveys FROM demo_links d ORDER BY d.created_at DESC")).rows));
  }));
  app.post("/admin/demo-links", requireUser, requireTeam, wrap(async (req, res) => {
    const label = str(req.body?.label) || "Demo link";
    const token = crypto.randomBytes(12).toString("base64url");
    const row = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const r = await c.query("INSERT INTO demo_links (token, label, created_by) VALUES ($1,$2,$3) RETURNING id, token, label, active, views, created_at", [token, label, req.user.email]);
      await audit(c, req, null, "admin.demo_link_create", r.rows[0].id);
      return r.rows[0];
    });
    res.status(201).json(row);
  }));
  app.patch("/admin/demo-links/:id", requireUser, requireTeam, wrap(async (req, res) => {
    if (!isUuid(req.params.id)) throw new HttpError(404, "not_found");
    const row = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const r = await c.query("UPDATE demo_links SET active = $2 WHERE id = $1 RETURNING id, token, label, active, views", [req.params.id, !!req.body?.active]);
      if (!r.rowCount) throw new HttpError(404, "not_found");
      await audit(c, req, null, "admin.demo_link_update", req.params.id, { active: !!req.body?.active });
      return r.rows[0];
    });
    res.json(row);
  }));
  app.get("/admin/feedback", requireUser, requireTeam, wrap(async (req, res) => {
    res.json(await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => (await c.query(
      `SELECT f.id, f.kind, f.rating, f.message, f.answers, f.contact, f.screen, f.role, f.user_email, f.language, f.created_at, p.name AS provider, d.label AS demo_label
       FROM feedback f LEFT JOIN providers p ON p.id = f.provider_id LEFT JOIN demo_links d ON d.id = f.demo_link_id
       ORDER BY f.created_at DESC LIMIT 500`)).rows));
  }));

  // Alaga team: every daycare, with counts. Verified team emails only.
  app.get("/admin/providers", requireUser, wrap(async (req, res) => {
    if (!req.user.emailVerified || !admins.includes(req.user.email)) throw new HttpError(403, "no_access");
    const rows = await withContext(pool, { role: "system", uid: req.user.uid }, async (c) => {
      const r = await c.query(`SELECT p.id, p.name, p.city, p.capacity, p.created_at,
          (SELECT count(*) FROM children k WHERE k.provider_id = p.id AND k.status = 'active')::int AS children,
          (SELECT count(*) FROM guardians g WHERE g.provider_id = p.id AND g.user_uid IS NOT NULL)::int AS parents_with_access
        FROM providers p ORDER BY p.created_at DESC`);
      await audit(c, req, null, "admin.providers_view", null);
      return r.rows;
    });
    res.json(rows);
  }));

  app.use((req, res) => res.status(404).json({ error: "not_found" }));
  return app;
}

function inviteState(inv) {
  if (!inv) return { status: "none" };
  if (inv.revoked_at) return { status: "revoked" };
  if (inv.used_at) return { status: "accepted", usedAt: inv.used_at, id: inv.id };
  if (new Date(inv.expires_at) < new Date()) return { status: "expired", id: inv.id };
  return { status: "pending", expiresAt: inv.expires_at, id: inv.id };
}
