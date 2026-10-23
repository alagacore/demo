// Database access. On Cloud Run the database is reached through the built-in
// Cloud SQL connection (a socket under /cloudsql); locally, DATABASE_URL.
import pg from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;

export function makePool(env = process.env) {
  if (env.DATABASE_URL) return new Pool({ connectionString: env.DATABASE_URL, max: 5 });
  return new Pool({
    host: `/cloudsql/${env.INSTANCE_CONNECTION_NAME}`,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    max: 5,                // small pool: Cloud Run scales instances instead
    idleTimeoutMillis: 30000,
  });
}

// Runs fn inside a transaction with the request's identity set, so the
// database's row-level security applies to every query in it.
export async function withContext(pool, ctx, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT set_config('app.role', $1, true), set_config('app.user_id', $2, true), set_config('app.provider_id', $3, true), set_config('app.household_id', $4, true)",
      [ctx.role || "", ctx.uid || "", ctx.providerId || "", ctx.householdId || ""],
    );
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// Applies any migration files that haven't run yet, in order, once each.
export async function migrate(pool) {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock(424242)"); // one instance migrates at a time
    await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    const done = new Set((await client.query("SELECT name FROM schema_migrations")).rows.map((r) => r.name));
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
      if (done.has(file)) continue;
      await client.query("BEGIN");
      try {
        await client.query(fs.readFileSync(path.join(dir, file), "utf8"));
        await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
        await client.query("COMMIT");
        console.log(`migrated ${file}`);
      } catch (e) {
        await client.query("ROLLBACK");
        throw new Error(`migration ${file} failed: ${e.message}`);
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock(424242)").catch(() => {});
    client.release();
  }
}
