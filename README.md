# jnex-server (M1)

The Jnex cloud server. It runs on **Cloudflare Workers** (free plan, no card needed) and stores data in
**Neon Postgres**.

What M1 does:

* **Shop owners** (JnexHub): email + password, then the 6-digit authenticator code. Sessions, "sign out everywhere".
* **POS machines**: a machine registers with the shop code, you approve it, it receives a **signed licence** (works offline)
  and a short access token. Each machine gets a letter (A, B, C...) for bill numbers.
* **Admin page** (`/admin`): create shops, owner logins, approve machines, extend licences, reset a locked-out owner.

Not in M1 yet: syncing sales (M2/M3), JnexHub data endpoints, backups to R2, AI assistant.

---

## 1. First-time setup (on your PC)

You need Node.js 20 or newer (`node -v`).

```
npm install
npm run secrets
```

`npm run secrets` prints 5 secret values. **Copy them into your private notes** (Bitwarden / phone note).
Do not paste them in chat or on GitHub.

Make your local settings file:

1. Copy `.dev.vars.example` to a new file named `.dev.vars` (same folder).
2. Fill it in:
   * `DATABASE_URL`: Neon "Connect" with **pooling ON** (the host has `-pooler`).
   * `DATABASE_URL_DIRECT`: Neon "Connect" with **pooling OFF**.
   * the 5 values from `npm run secrets`.

`.dev.vars` is already in `.gitignore`: it will never be uploaded.

## 2. Create the database tables

```
npm run migrate
```

Expected: `Running 0001_init.sql ...` then `Done. 1 migration(s) applied.`
(Running it again says "already up to date": safe.)

## 3. Try it on your PC

```
npm test          # 20 automatic tests (no database needed)
npm run dev
```

Open <http://localhost:8787/health>: you should see `{"ok":true,"db":true,...}`.
Open <http://localhost:8787/admin>, paste your `ADMIN_API_KEY`, click **Connect**.

## 4. Put it online (Cloudflare)

Easiest way, from this folder:

```
npx wrangler login
npx wrangler secret put DATABASE_URL
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put JWT_SECRET
npx wrangler secret put DATA_KEY
npx wrangler secret put LICENSE_PRIVATE_KEY
npx wrangler secret put LICENSE_PUBLIC_KEY
npx wrangler deploy
```

Each `secret put` asks you to paste the value (it is not shown on screen).
`deploy` prints an address like `https://jnex-server.<your-name>.workers.dev`.
Check `<that address>/health`.

Later, give it a nice address: Cloudflare dashboard -> Workers & Pages -> jnex-server -> Settings ->
Domains & Routes -> Add -> Custom domain -> `api.jnex.com.lk`.
Then edit `ALLOWED_ORIGINS` in `wrangler.toml` to the website(s) that may call the API (for example `https://hub.jnex.com.lk`).

## 5. Your first shop

1. Open `<your address>/admin`, paste the `ADMIN_API_KEY`, **Connect**.
2. **New shop** -> name + licence days -> **Create shop**. You get a **shop code** like `JX-4F7K2M9P`.
3. On that shop's row click **+ Owner** -> email + name. A **temporary password** is shown **once**: give it to the owner.
4. The owner signs in (JnexHub, later), sets up the authenticator app and chooses a new password.
5. When a POS machine registers with the shop code it appears under **Machines waiting for approval** -> **Approve**.

## Security notes

* Passwords are hashed with bcrypt **inside Postgres**; the server never stores or logs them.
* Session tokens, login steps: only a hash is stored. Authenticator secrets are encrypted (AES-GCM) with `DATA_KEY`.
* Wrong passwords: 5 tries per 5 minutes per email. Wrong authenticator codes: 5 tries per login. A code works once.
* Admin key: 10 wrong tries per 10 minutes per network address.
* Cookies are `HttpOnly`, `Secure`, `SameSite=Lax`; other websites cannot make changes with them.
* If you ever suspect a secret leaked: create a new one (`npm run secrets`), `wrangler secret put` it, redeploy.
  A new `DATA_KEY` means owners must set up their authenticator again; a new `LICENSE_*` pair means machines must fetch a new licence.

## API (summary)

| Who | Method + path |
|---|---|
| Anyone | `GET /health`, `GET /v1/license/public-key` |
| Owner | `POST /v1/auth/login`, `/mfa/setup`, `/mfa/enable`, `/mfa/verify`, `/logout`, `/logout-all`, `/password`; `GET /v1/auth/session`, `/sessions`; `DELETE /v1/auth/sessions/:id` |
| POS machine | `POST /v1/devices/register`, `POST /v1/devices/:id/token`, `GET /v1/device/ping` |
| Jnex admin (Bearer `ADMIN_API_KEY`) | `/v1/admin/tenants`, `/tenants/:id/owners`, `/tenants/:id/license`, `/devices`, `/devices/:id/approve`, `/devices/:id/revoke`, `/owners/:id/reset` |

A POS machine proves itself by signing `jnex-device-token|<device id>|<unix seconds>` with its own Ed25519 key.
The licence it receives is `base64url(payload).base64url(signature)`; the POS app verifies it offline with the public key.
