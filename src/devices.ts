// POS machines: register -> the vendor approves -> the machine collects a signed
// licence + a short-lived access token. Machines never send a password: they
// prove who they are by signing a message with their own private key.
import type { Ctx, Device, Env, Tenant } from "./types";
import { HttpError, json, readJson, str } from "./http";
import { b64uDecode, b64uEncode, ed25519Sign, ed25519Verify, fromUtf8, signJwt, utf8, verifyJwt } from "./crypto";

export const LICENSE_GRACE_DAYS = 14; // how long a machine may keep working offline after the licence date
const ACCESS_TTL_SEC = 15 * 60;
const SIGNATURE_WINDOW_SEC = 300;

// A, B, C ... Z, AA, AB ...  (printed in front of bill numbers: A-1042)
export function deviceCodeFor(index: number): string {
  let n = index;
  let s = "";
  do {
    s = String.fromCharCode(65 + (n % 26)) + s;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return s;
}

export function normalizeShopCode(v: unknown): string {
  return str(v, "shop code", 4, 40).toUpperCase().replace(/[\s_]/g, "");
}

// ---- licence token: base64url(payload) + "." + base64url(Ed25519 signature) ----
export interface LicensePayload {
  v: 1;
  tid: string;
  did: string;
  code: string | null;
  shop: string;
  plan: string;
  exp: number | null; // unix seconds, null = no expiry
  grace: number; // days
  iat: number;
  hw: string;
}
export async function makeLicense(env: Env, tenant: Tenant, device: Device, nowSec: number): Promise<string> {
  const payload: LicensePayload = {
    v: 1,
    tid: tenant.id,
    did: device.id,
    code: device.deviceCode,
    shop: tenant.name,
    plan: tenant.plan,
    exp: tenant.licenseExpiresAt ? Math.floor(Date.parse(tenant.licenseExpiresAt) / 1000) : null,
    grace: LICENSE_GRACE_DAYS,
    iat: nowSec,
    hw: device.hwHash,
  };
  const body = b64uEncode(utf8(JSON.stringify(payload)));
  const sig = await ed25519Sign(env.LICENSE_PRIVATE_KEY, utf8(body));
  return `${body}.${b64uEncode(sig)}`;
}
// The POS app does the same check offline with the public key built into it.
export async function verifyLicense(token: string, publicKeyB64u: string): Promise<LicensePayload | null> {
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  if (!(await ed25519Verify(publicKeyB64u, b64uDecode(sig), utf8(body)))) return null;
  try {
    return JSON.parse(fromUtf8(b64uDecode(body))) as LicensePayload;
  } catch {
    return null;
  }
}

function publicDevice(d: Device) {
  return { id: d.id, name: d.name, status: d.status, deviceCode: d.deviceCode };
}

// ---- POS -> server ----------------------------------------------------------
export async function registerDevice(ctx: Ctx): Promise<Response> {
  const body = await readJson(ctx.req);
  const code = normalizeShopCode(body.shopCode);
  const name = str(body.name ?? "POS", "name", 1, 60);
  const hwHash = str(body.hwHash, "hwHash", 16, 128);
  const publicKey = str(body.publicKey, "publicKey", 40, 50);
  const appVersion = typeof body.appVersion === "string" ? body.appVersion.slice(0, 32) : null;
  try {
    if (b64uDecode(publicKey).length !== 32) throw new Error();
  } catch {
    throw new HttpError(400, "invalid_input", "publicKey must be a raw Ed25519 key (base64url).");
  }

  if ((await ctx.repo.rateCount(`reg-ip:${ctx.ip}`, 3600)) >= 10) {
    throw new HttpError(429, "too_many_attempts", "Too many registrations from this network. Try again later.", { retryAfter: 3600 });
  }
  await ctx.repo.rateHit(`reg-ip:${ctx.ip}`, 3600);

  const tenant = await ctx.repo.getTenantByCode(code);
  if (!tenant || tenant.status !== "active") throw new HttpError(404, "unknown_shop", "That shop code is not valid.");

  // same machine registering again (e.g. app restarted) -> same record
  const existing = await ctx.repo.findDeviceByKey(tenant.id, publicKey);
  if (existing) return json({ device: publicDevice(existing) });

  if ((await ctx.repo.rateCount(`reg-tenant:${tenant.id}`, 86400)) >= 30) {
    throw new HttpError(429, "too_many_attempts", "Too many registrations for this shop today.", { retryAfter: 3600 });
  }
  await ctx.repo.rateHit(`reg-tenant:${tenant.id}`, 86400);

  const device = await ctx.repo.createDevice({ tenantId: tenant.id, name, hwHash, publicKey, appVersion });
  await ctx.repo.audit({ tenantId: tenant.id, actor: `device:${device.id}`, action: "device.registered", details: { name, ip: ctx.ip } });
  return json({ device: publicDevice(device) }, 201);
}

// The machine asks "am I approved yet?" by signing "jnex-device-token|<id>|<unix seconds>".
export async function deviceToken(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  const body = await readJson(ctx.req);
  const ts = Number(body.ts);
  const sig = str(body.sig, "sig", 20, 200);
  const nowSec = Math.floor(ctx.now().getTime() / 1000);
  if (!Number.isInteger(ts) || Math.abs(nowSec - ts) > SIGNATURE_WINDOW_SEC) {
    throw new HttpError(401, "stale_request", "Check that this computer's clock is correct.");
  }
  const device = await ctx.repo.getDevice(params.id);
  let signatureOk = false;
  if (device) {
    try {
      signatureOk = await ed25519Verify(device.publicKey, b64uDecode(sig), utf8(`jnex-device-token|${device.id}|${ts}`));
    } catch {
      signatureOk = false;
    }
  }
  if (!device || !signatureOk) throw new HttpError(401, "bad_signature", "Could not verify this machine.");

  if (device.status === "pending") return json({ status: "pending" }, 202);
  if (device.status === "revoked") throw new HttpError(403, "device_revoked", "This machine has been deactivated.", { status: "revoked" });

  const tenant = await ctx.repo.getTenant(device.tenantId);
  if (!tenant || tenant.status !== "active") throw new HttpError(403, "tenant_suspended", "This shop account is suspended.", { status: "suspended" });
  if (tenant.licenseExpiresAt && Date.parse(tenant.licenseExpiresAt) <= ctx.now().getTime()) {
    throw new HttpError(402, "license_expired", "The licence has expired. Please renew.", { status: "license_expired", licenseExpiresAt: tenant.licenseExpiresAt });
  }

  const accessToken = await signJwt({ typ: "device", sub: device.id, tid: device.tenantId, exp: nowSec + ACCESS_TTL_SEC }, ctx.env.JWT_SECRET);
  return json({
    status: "active",
    deviceCode: device.deviceCode,
    shopName: tenant.name,
    license: await makeLicense(ctx.env, tenant, device, nowSec),
    accessToken,
    accessExpiresAt: new Date((nowSec + ACCESS_TTL_SEC) * 1000).toISOString(),
    serverTime: ctx.now().toISOString(),
  });
}

export async function requireDevice(ctx: Ctx): Promise<{ device: Device; tenant: Tenant }> {
  const h = ctx.req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  const claims = token ? await verifyJwt(token, ctx.env.JWT_SECRET, Math.floor(ctx.now().getTime() / 1000)) : null;
  if (!claims || claims.typ !== "device" || typeof claims.sub !== "string") throw new HttpError(401, "bad_token", "Sign in again.");
  const device = await ctx.repo.getDevice(claims.sub);
  if (!device || device.status !== "active") throw new HttpError(403, "device_revoked", "This machine has been deactivated.");
  const tenant = await ctx.repo.getTenant(device.tenantId);
  if (!tenant || tenant.status !== "active") throw new HttpError(403, "tenant_suspended", "This shop account is suspended.");
  return { device, tenant };
}

// Heartbeat: shows the machine as "online" in the dashboard and records its app version.
export async function devicePing(ctx: Ctx): Promise<Response> {
  const { device, tenant } = await requireDevice(ctx);
  const v = ctx.req.headers.get("x-app-version");
  await ctx.repo.touchDevice(device.id, v ? v.slice(0, 32) : null);
  return json({ ok: true, serverTime: ctx.now().toISOString(), deviceCode: device.deviceCode, shopName: tenant.name, licenseExpiresAt: tenant.licenseExpiresAt });
}

export async function licensePublicKey(ctx: Ctx): Promise<Response> {
  return json({ alg: "Ed25519", publicKey: ctx.env.LICENSE_PUBLIC_KEY });
}
