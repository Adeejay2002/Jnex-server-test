import type { Ctx, Env, Repo } from "./types";
import { HttpError, errorResponse, json } from "./http";
import { Router } from "./router";
import * as auth from "./auth";
import * as devices from "./devices";
import * as admin from "./admin";
import { randomToken } from "./crypto";
import { PgRepo } from "./pgrepo";

const router = new Router();
router.add("GET", "/health", async (ctx) => {
  const db = await ctx.repo.ping().catch(() => false);
  return json({ ok: db, db, time: ctx.now().toISOString() }, db ? 200 : 503);
});

// shop owners (JnexHub)
router.add("POST", "/v1/auth/login", auth.login);
router.add("POST", "/v1/auth/mfa/setup", auth.mfaSetup);
router.add("POST", "/v1/auth/mfa/enable", auth.mfaEnable);
router.add("POST", "/v1/auth/mfa/verify", auth.mfaVerify);
router.add("GET", "/v1/auth/session", auth.getSession);
router.add("POST", "/v1/auth/logout", auth.logout);
router.add("POST", "/v1/auth/logout-all", auth.logoutEverywhere);
router.add("GET", "/v1/auth/sessions", auth.listSessions);
router.add("DELETE", "/v1/auth/sessions/:id", auth.revokeSession);
router.add("POST", "/v1/auth/password", auth.changePassword);

// POS machines
router.add("POST", "/v1/devices/register", devices.registerDevice);
router.add("POST", "/v1/devices/:id/token", devices.deviceToken);
router.add("GET", "/v1/device/ping", devices.devicePing);
router.add("GET", "/v1/license/public-key", devices.licensePublicKey);

// Jnex staff
router.add("GET", "/v1/admin/tenants", admin.listTenants);
router.add("POST", "/v1/admin/tenants", admin.createTenant);
router.add("GET", "/v1/admin/tenants/:id/owners", admin.listOwners);
router.add("POST", "/v1/admin/tenants/:id/owners", admin.createOwner);
router.add("POST", "/v1/admin/tenants/:id/license", admin.extendLicense);
router.add("GET", "/v1/admin/devices", admin.listDevices);
router.add("POST", "/v1/admin/devices/:id/approve", admin.approveDevice);
router.add("POST", "/v1/admin/devices/:id/revoke", admin.revokeDevice);
router.add("POST", "/v1/admin/owners/:id/reset", admin.resetOwner);

function allowedOrigins(env: Env): string[] {
  return (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
}

const BASE_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "cache-control": "no-store",
};

function withHeaders(res: Response, extra: Record<string, string>): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...BASE_HEADERS, ...extra })) out.headers.set(k, v);
  return out;
}

export async function handle(req: Request, env: Env, repo: Repo, now: () => Date = () => new Date()): Promise<Response> {
  const url = new URL(req.url);
  const origin = req.headers.get("origin");
  const allowed = allowedOrigins(env);
  const originOk = !!origin && (allowed.includes(origin) || origin === url.origin);
  const cors: Record<string, string> = originOk
    ? { "access-control-allow-origin": origin!, "access-control-allow-credentials": "true", vary: "Origin" }
    : { vary: "Origin" };

  try {
    // browsers send a preflight first
    if (req.method === "OPTIONS") {
      if (!originOk) return withHeaders(new Response(null, { status: 403 }), {});
      return withHeaders(new Response(null, { status: 204 }), {
        ...cors,
        "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
        "access-control-allow-headers": "content-type,authorization,x-app-version",
        "access-control-max-age": "600",
      });
    }
    // a website that is not ours may not make changes with the owner's cookie
    if (req.method !== "GET" && req.method !== "HEAD" && origin && !originOk) {
      throw new HttpError(403, "origin_not_allowed", "This website is not allowed to call the server.");
    }

    if (req.method === "GET" && url.pathname === "/admin") {
      const nonce = randomToken(16);
      return withHeaders(new Response(admin.adminPage(nonce), { headers: { "content-type": "text/html; charset=utf-8" } }), {
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
    }

    const m = router.match(req.method === "HEAD" ? "GET" : req.method, url.pathname);
    if (m === null) throw new HttpError(404, "not_found", "No such page.");
    if (m === "method_not_allowed") throw new HttpError(405, "method_not_allowed", "Wrong method for this address.");

    const ctx: Ctx = {
      env,
      repo,
      req,
      url,
      ip: req.headers.get("cf-connecting-ip") || "unknown",
      userAgent: (req.headers.get("user-agent") || "").slice(0, 200) || null,
      now,
    };
    return withHeaders(await m.handler(ctx, m.params), cors);
  } catch (e) {
    if (e instanceof HttpError) return withHeaders(errorResponse(e), cors);
    console.error("Unhandled error:", e instanceof Error ? `${e.name}: ${e.message}` : String(e));
    return withHeaders(json({ error: { code: "server_error", message: "Something went wrong on the server." } }, 500), cors);
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    return handle(req, env, new PgRepo(env.DATABASE_URL));
  },
  async scheduled(_event: unknown, env: Env): Promise<void> {
    await new PgRepo(env.DATABASE_URL).purgeExpired();
  },
};
