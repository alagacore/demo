// Checks the Firebase sign-in token sent with each request.
import { initializeApp, applicationDefault } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";

let verify;

export function setupAuth(env = process.env) {
  // Test mode accepts "test:<uid>:<email>[:verified]" tokens. It refuses to
  // start on Cloud Run (K_SERVICE is set there), so it can't be left on.
  if (env.AUTH_TEST_MODE === "1") {
    if (env.K_SERVICE || env.NODE_ENV === "production") throw new Error("AUTH_TEST_MODE cannot run in production");
    verify = async (token) => {
      // Also accepts unsigned test JWTs from the website's browser tests.
      if (token.split(".").length === 3) {
        const c = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
        return { uid: c.user_id || c.sub, email: c.email, email_verified: !!c.email_verified };
      }
      const [tag, uid, email, verified] = token.split(":");
      if (tag !== "test" || !uid) throw new Error("bad test token");
      return { uid, email, email_verified: verified === "verified" };
    };
    return;
  }
  const app = initializeApp({ credential: applicationDefault(), projectId: env.FIREBASE_PROJECT_ID || "alaga-production" });
  const auth = getAuth(app);
  // Checks the token's signature, expiry and project. (Also rejecting revoked
  // sessions needs the "Firebase Authentication Viewer" role on the service
  // account; set FIREBASE_CHECK_REVOKED=1 after granting it.)
  const checkRevoked = env.FIREBASE_CHECK_REVOKED === "1";
  verify = (token) => auth.verifyIdToken(token, checkRevoked);
}

export async function requireUser(req, res, next) {
  const h = req.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ error: "sign_in_required" });
  try {
    const d = await verify(token);
    req.user = { uid: d.uid, email: String(d.email || "").toLowerCase(), emailVerified: !!d.email_verified };
    next();
  } catch (e) {
    res.status(401).json({ error: "sign_in_expired" });
  }
}

// Like requireUser, but lets the request through without a sign-in.
export async function optionalUser(req, res, next) {
  const h = req.get("authorization") || "";
  if (!h.startsWith("Bearer ")) return next();
  try {
    const d = await verify(h.slice(7));
    req.user = { uid: d.uid, email: String(d.email || "").toLowerCase(), emailVerified: !!d.email_verified };
  } catch (e) { /* treat as signed out */ }
  next();
}
