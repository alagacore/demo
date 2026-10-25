// Site lock. Runs on Vercel before any page loads, so the public can't see
// the site without the beta password. Real accounts and data are protected
// separately by sign-in and the Alaga API; this just keeps the site private.
//
// Set SITE_PASSWORD in Vercel → Settings → Environment Variables.
// Changing it signs everyone out of the lock.
//
// People arriving with a link Alaga gave them (a family invite, a beta code,
// a private demo link, or the door QR code) skip the password, because the
// link itself is their way in. The app still checks every code with the API.
import { next } from "@vercel/functions";
import crypto from "node:crypto";

const COOKIE = "alaga_gate";
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

const LINK_PARAMS = {
  invite: /^[A-HJ-NP-Z2-9]{4}-?[A-HJ-NP-Z2-9]{4}$/i,
  beta: /^[A-HJ-NP-Z2-9]{4}-?[A-HJ-NP-Z2-9]{4}$/i,
  demo: /^[A-Za-z0-9_-]{16}$/,
  checkin: /^[A-Za-z0-9_-]{0,64}$/,
};

const pass = (pw) => crypto.createHmac("sha256", pw).update("alaga-gate-v1").digest("hex");
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const cookieOf = (req) => (req.headers.get("cookie") || "").split(/;\s*/).map((c) => c.split("=")).find(([k]) => k === COOKIE)?.[1] || "";
const setCookie = (v) => `${COOKIE}=${v}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
const safeBack = (p) => (typeof p === "string" && p.startsWith("/") && !p.startsWith("//") ? p : "/");

export default async function proxy(request) {
  const url = new URL(request.url);
  const pw = process.env.SITE_PASSWORD || "";
  const good = pw ? pass(pw) : "";

  // Unlock form
  if (url.pathname === "/__unlock" && request.method === "POST") {
    const form = new URLSearchParams(await request.text());
    const back = safeBack(form.get("back"));
    if (pw && same(pass(form.get("password") || ""), good)) {
      return new Response(null, { status: 303, headers: { Location: back, "Set-Cookie": setCookie(good), "Cache-Control": "no-store" } });
    }
    await new Promise((r) => setTimeout(r, 800)); // slow down guessing
    return lockPage(back, pw ? "That password isn't right." : "The site lock isn't set up yet.", 401);
  }

  // Already unlocked
  if (good && same(cookieOf(request), good)) return next();

  // Arrived with an Alaga link: let them in and remember it
  for (const [key, re] of Object.entries(LINK_PARAMS)) {
    if (url.searchParams.has(key) && re.test(url.searchParams.get(key) || "")) {
      return good ? next({ headers: { "Set-Cookie": setCookie(good) } }) : next();
    }
  }

  return lockPage(url.pathname + url.search, "", pw ? 401 : 503);
}

function lockPage(back, error, status) {
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Alaga — private beta</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Fraunces:wght@600&family=Work+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:#FAF6EF;font-family:'Work Sans',system-ui,sans-serif;color:#2B2622}
.card{width:100%;max-width:380px;background:#fff;border:1px solid #E8E0D2;border-radius:18px;padding:28px 24px;text-align:center}
.logo{font-family:'Fraunces',Georgia,serif;font-size:34px;font-weight:600;color:#A4561F;margin:0 0 6px}
p{margin:0 0 18px;color:#6E655B;font-size:14.5px;line-height:1.5}
input{width:100%;padding:12px;border:1px solid #E8E0D2;border-radius:10px;font-size:16px;margin-bottom:12px;font-family:inherit}
input:focus{outline:2px solid #E3A72F;border-color:transparent}
button{width:100%;padding:12px;border:0;border-radius:10px;background:#B35A20;color:#fff;font-weight:700;font-size:15px;font-family:inherit;cursor:pointer}
.err{color:#B3261E;font-size:13.5px;margin:0 0 12px}.foot{margin-top:16px;font-size:12.5px;color:#8A8177}
</style></head><body><main class="card">
<div class="logo">alaga</div>
<p>Alaga is in private beta. Enter the beta password to continue.</p>
${error ? `<div class="err" role="alert">${esc(error)}</div>` : ""}
<form method="post" action="/__unlock">
<input type="hidden" name="back" value="${esc(back)}">
<input type="password" name="password" placeholder="Beta password" autocomplete="current-password" required autofocus aria-label="Beta password">
<button type="submit">Continue</button>
</form>
<div class="foot">Got an invite or demo link? Open that link directly.</div>
</main></body></html>`;
  return new Response(html, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow" } });
}
