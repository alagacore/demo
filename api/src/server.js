import { makePool, migrate } from "./db.js";
import { setupAuth } from "./auth.js";
import { makeApp } from "./app.js";

const pool = makePool();
setupAuth();
await migrate(pool);
const port = Number(process.env.PORT) || 8080;
makeApp({ pool }).listen(port, () => console.log(`alaga-api listening on ${port}`));
