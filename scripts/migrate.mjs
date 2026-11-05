// Creates / upgrades the database tables:  npm run migrate
// Needs DATABASE_URL_DIRECT (Neon "Connect" with pooling OFF) in .dev.vars or in the environment.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function loadVars() {
  const file = join(root, ".dev.vars");
  const vars = {};
  if (existsSync(file)) {
    for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !line.trim().startsWith("#")) vars[m[1]] = m[2].replace(/^['"]|['"]$/g, "");
    }
  }
  return vars;
}

const vars = loadVars();
const url = process.env.DATABASE_URL_DIRECT || vars.DATABASE_URL_DIRECT || process.env.DATABASE_URL || vars.DATABASE_URL;
if (!url) {
  console.error('No database address. Put DATABASE_URL_DIRECT=... in the ".dev.vars" file (see .dev.vars.example).');
  process.exit(1);
}

const client = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: true } });
await client.connect();
try {
  await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const done = new Set((await client.query("SELECT id FROM schema_migrations")).rows.map((r) => r.id));
  const files = readdirSync(join(root, "migrations")).filter((f) => f.endsWith(".sql")).sort();
  let ran = 0;
  for (const f of files) {
    if (done.has(f)) continue;
    console.log("Running", f, "...");
    await client.query("BEGIN");
    try {
      await client.query(readFileSync(join(root, "migrations", f), "utf8"));
      await client.query("INSERT INTO schema_migrations (id) VALUES ($1)", [f]);
      await client.query("COMMIT");
      ran++;
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    }
  }
  console.log(ran ? `Done. ${ran} migration(s) applied.` : "Database is already up to date.");
} finally {
  await client.end();
}
