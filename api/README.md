# Alaga API

Runs on Cloud Run (us-west1) and stores data in Cloud SQL for PostgreSQL.
The website signs people in with Firebase; every request sends that sign-in
token, and this API checks it before touching the database.

## How data stays separate

- Every row carries its daycare's id.
- Postgres row-level security (forced, so it applies even to the table owner)
  only shows rows for the daycare, or the one family, set for the request.
  The API sets that from the user's verified membership, never from the request.
- Invite codes are stored only as a hash, work once, only for the invited
  email, expire after 7 days, and guessing is rate limited.
- `audit_log` records views and changes; rows can't be edited or deleted.

## Environment (Cloud Run)

| Variable | Value |
| --- | --- |
| `INSTANCE_CONNECTION_NAME` | `alaga-production:us-west1:<instance>` |
| `DB_NAME` | `alaga` |
| `DB_USER` | `alaga_app` |
| `DB_PASSWORD` | from Secret Manager secret `DB_PASSWORD` |
| `ADMIN_EMAILS` | `hello@alagacore.com` |
| `ALLOWED_ORIGINS` | `https://alaga-master-8426.vercel.app` |

Migrations in `migrations/` run automatically when the service starts.

## One-time database permission

`alaga_app` must own the database's `public` schema so migrations can create
tables. In Cloud SQL Studio, signed in as `postgres`:

```sql
ALTER DATABASE alaga OWNER TO alaga_app;
ALTER SCHEMA public OWNER TO alaga_app;
```

## Tests

`npm test` starts a throwaway local Postgres, connects as a non-superuser like
production, and checks separation between daycares, invites, the audit log and
team access.
