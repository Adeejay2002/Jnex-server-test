import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign, randomBytes } from "node:crypto";
import { handle } from "../src/index";
import { MemRepo } from "./memrepo";
import { b64Encode, b64uEncode, decryptString, utf8 } from "../src/crypto";
import { totpCode } from "../src/totp";
import { verifyLicense } from "../src/devices";
import type { Env } from "../src/types";

const ed = generateKeyPairSync("ed25519");
const ADMIN = "x".repeat(40);
const env: Env = {
  DATABASE_URL: "unused",
  ADMIN_API_KEY: ADMIN,
  JWT_SECRET: "j".repeat(40),
  DATA_KEY: b64Encode(new Uint8Array(randomBytes(32))),
  LICENSE_PRIVATE_KEY: ed.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
  LICENSE_PUBLIC_KEY: String(ed.publicKey.export({ format: "jwk" }).x),
  ALLOWED_ORIGINS: "https://hub.example.lk",
  ENVIRONMENT: "production",
};

class Client {
  cookie = "";
  constructor(public repo: MemRepo, public clock: { ms: number }, public ip = "1.1.1.1") {}
  async call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { "cf-connecting-ip": this.ip, ...headers };
    if (body !== undefined) h["content-type"] = "application/json";
    if (this.cookie) h.cookie = this.cookie;
    const res = await handle(new Request("https://api.example.lk" + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, this.repo, () => new Date(this.clock.ms));
    const sc = res.headers.get("set-cookie");
    if (sc) this.cookie = sc.includes("Max-Age=0") ? "" : sc.split(";")[0];
    const text = await res.text();
    let data: any = null;
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data, headers: res.headers };
  }
  admin(method: string, path: string, body?: unknown) { return this.call(method, path, body, { authorization: `Bearer ${ADMIN}` }); }
}
const fresh = () => {
  const clock = { ms: Date.UTC(2026, 9, 28, 10, 0, 0) };
  const repo = new MemRepo();
  repo.clock = () => clock.ms;
  return { repo, clock, c: new Client(repo, clock) };
};

async function shopWithOwner(c: Client) {
  const t = await c.admin("POST", "/v1/admin/tenants", { name: "Test Mart", licenseDays: 30 });
  assert.equal(t.status, 201);
  const o = await c.admin("POST", `/v1/admin/tenants/${t.data.tenant.id}/owners`, { email: "Owner@Test.lk", name: "Owner" });
  assert.equal(o.status, 201);
  return { tenant: t.data.tenant, temp: o.data.temporaryPassword as string };
}

test("health, 404, 405, security headers", async () => {
  const { c } = fresh();
  const h = await c.call("GET", "/health");
  assert.equal(h.status, 200);
  assert.equal(h.headers.get("x-content-type-options"), "nosniff");
  assert.equal((await c.call("GET", "/nope")).status, 404);
  assert.equal((await c.call("GET", "/v1/auth/login")).status, 405);
});

test("admin endpoints need the admin key; wrong keys are rate limited", async () => {
  const { c } = fresh();
  assert.equal((await c.call("GET", "/v1/admin/tenants")).status, 401);
  assert.equal((await c.call("GET", "/v1/admin/tenants", undefined, { authorization: "Bearer nope" })).status, 401);
  assert.equal((await c.admin("GET", "/v1/admin/tenants")).status, 200);
  for (let i = 0; i < 10; i++) await c.call("GET", "/v1/admin/tenants", undefined, { authorization: "Bearer bad" });
  assert.equal((await c.admin("GET", "/v1/admin/tenants")).status, 429); // even the right key is refused for a while
});

test("owner journey: login -> set up authenticator -> change temp password -> logout -> login with code", async () => {
  const { repo, clock, c } = fresh();
  const { temp } = await shopWithOwner(c);

  let r = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: "wrong-password" });
  assert.equal(r.status, 401);
  assert.equal(r.data.error.code, "invalid_credentials");
  r = await c.call("POST", "/v1/auth/login", { email: "ghost@test.lk", password: "wrong-password" });
  assert.equal(r.status, 401);
  assert.equal(r.data.error.message, "Wrong email or password.");

  r = await c.call("POST", "/v1/auth/login", { email: "OWNER@test.lk", password: temp });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, "mfa_setup_required");
  assert.equal(r.data.mustChangePassword, true);
  const ch = r.data.challenge;
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 401);

  r = await c.call("POST", "/v1/auth/mfa/setup", { challenge: ch });
  assert.equal(r.status, 200);
  assert.match(r.data.otpauthUri, /^otpauth:\/\/totp\//);
  const secret: string = r.data.secret;
  assert.ok(!repo.owners[0].mfaSecretEnc!.includes(secret), "secret is not stored in plain text");
  assert.equal(await decryptString(repo.owners[0].mfaSecretEnc!, env.DATA_KEY), secret);

  r = await c.call("POST", "/v1/auth/mfa/enable", { challenge: ch, code: "000000" });
  assert.equal(r.status, 401);
  r = await c.call("POST", "/v1/auth/mfa/enable", { challenge: ch, code: await totpCode(secret, clock.ms) });
  assert.equal(r.status, 200);
  assert.equal(r.data.owner.shopName, "Test Mart");
  const setCookie = r.headers.get("set-cookie")!;
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Lax/);
  assert.ok(!JSON.stringify(repo.sessions).includes(c.cookie.split("=")[1]), "only a hash of the session token is stored");

  assert.equal((await c.call("GET", "/v1/auth/session")).data.owner.mustChangePassword, true);
  r = await c.call("GET", "/v1/auth/sessions");
  assert.equal(r.status, 403);
  assert.equal(r.data.error.code, "password_change_required");

  r = await c.call("POST", "/v1/auth/password", { current: temp, next: "short1" });
  assert.equal(r.status, 400);
  r = await c.call("POST", "/v1/auth/password", { current: temp, next: "onlyletterspassword" });
  assert.equal(r.status, 400);
  r = await c.call("POST", "/v1/auth/password", { current: "not-it", next: "Better-pass-2026" });
  assert.equal(r.status, 401);
  r = await c.call("POST", "/v1/auth/password", { current: temp, next: "Better-pass-2026" });
  assert.equal(r.status, 200);
  assert.equal((await c.call("GET", "/v1/auth/sessions")).status, 200);

  const oldCookie = c.cookie;
  assert.equal((await c.call("POST", "/v1/auth/logout")).status, 200);
  c.cookie = oldCookie;
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 401);
  c.cookie = "";

  clock.ms += 31_000;
  r = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: "Better-pass-2026" });
  assert.equal(r.data.status, "mfa_required");
  const code = await totpCode(secret, clock.ms);
  r = await c.call("POST", "/v1/auth/mfa/verify", { challenge: r.data.challenge, code });
  assert.equal(r.status, 200);
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 200);

  const c2 = new Client(repo, clock, "2.2.2.2");
  const l2 = await c2.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: "Better-pass-2026" });
  const replay = await c2.call("POST", "/v1/auth/mfa/verify", { challenge: l2.data.challenge, code });
  assert.equal(replay.status, 401);
  assert.equal(replay.data.error.code, "invalid_code");

  const list = await c.call("GET", "/v1/auth/sessions");
  assert.equal(list.data.sessions.filter((s: any) => s.current).length, 1);
  const keep = c.cookie;
  assert.equal((await c.call("POST", "/v1/auth/logout-all")).status, 200);
  c.cookie = keep;
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 401);
  assert.ok(repo.audits.some((a) => a.action === "owner.login"));
  assert.ok(repo.audits.some((a) => a.action === "owner.password_changed"));
});

test("5 wrong passwords lock the account for a while (even the right password)", async () => {
  const { c } = fresh();
  const { temp } = await shopWithOwner(c);
  for (let i = 0; i < 5; i++) assert.equal((await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: "nope-nope-1" })).status, 401);
  const r = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: temp });
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), "300");
});

test("5 wrong authenticator codes cancel the sign-in", async () => {
  const { c } = fresh();
  const { temp } = await shopWithOwner(c);
  const l = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: temp });
  await c.call("POST", "/v1/auth/mfa/setup", { challenge: l.data.challenge });
  for (let i = 0; i < 4; i++) assert.equal((await c.call("POST", "/v1/auth/mfa/enable", { challenge: l.data.challenge, code: "111111" })).data.error.code, "invalid_code");
  assert.equal((await c.call("POST", "/v1/auth/mfa/enable", { challenge: l.data.challenge, code: "111111" })).data.error.code, "challenge_invalid");
});

test("expired login steps are refused", async () => {
  const { clock, c } = fresh();
  const { temp } = await shopWithOwner(c);
  const l = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: temp });
  clock.ms += 11 * 60 * 1000;
  assert.equal((await c.call("POST", "/v1/auth/mfa/setup", { challenge: l.data.challenge })).status, 401);
});

test("browser protection: other websites cannot post with the cookie; allowed website can", async () => {
  const { c } = fresh();
  let r = await c.call("POST", "/v1/auth/logout", {}, { origin: "https://evil.example" });
  assert.equal(r.status, 403);
  r = await c.call("POST", "/v1/auth/logout", {}, { origin: "https://hub.example.lk" });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("access-control-allow-origin"), "https://hub.example.lk");
  assert.equal(r.headers.get("access-control-allow-credentials"), "true");
  r = await c.call("OPTIONS", "/v1/auth/login", undefined, { origin: "https://hub.example.lk" });
  assert.equal(r.status, 204);
  r = await c.call("OPTIONS", "/v1/auth/login", undefined, { origin: "https://evil.example" });
  assert.equal(r.status, 403);
  r = await c.call("POST", "/v1/auth/login", undefined, { "content-type": "text/plain" });
  assert.equal(r.status, 415);
});

test("POS machine: register -> pending -> approve -> signed licence + token -> ping -> revoke", async () => {
  const { repo, clock, c } = fresh();
  const { tenant } = await shopWithOwner(c);
  const dev = generateKeyPairSync("ed25519");
  const publicKey = b64uEncode(Buffer.from(String(dev.publicKey.export({ format: "jwk" }).x), "base64url"));
  const signFor = (id: string, ts: number) => b64uEncode(nodeSign(null, utf8(`jnex-device-token|${id}|${ts}`), dev.privateKey));
  const ts = () => Math.floor(clock.ms / 1000);

  let r = await c.call("POST", "/v1/devices/register", { shopCode: "JX-WRONG000", name: "Counter 1", hwHash: "a".repeat(32), publicKey });
  assert.equal(r.status, 404);
  r = await c.call("POST", "/v1/devices/register", { shopCode: tenant.code.toLowerCase(), name: "Counter 1", hwHash: "a".repeat(32), publicKey: "short" });
  assert.equal(r.status, 400);
  r = await c.call("POST", "/v1/devices/register", { shopCode: tenant.code.toLowerCase(), name: "Counter 1", hwHash: "a".repeat(32), publicKey, appVersion: "1.7.0" });
  assert.equal(r.status, 201);
  assert.equal(r.data.device.status, "pending");
  const id = r.data.device.id;
  r = await c.call("POST", "/v1/devices/register", { shopCode: tenant.code, name: "Counter 1", hwHash: "a".repeat(32), publicKey });
  assert.equal(r.data.device.id, id);
  assert.equal(repo.devices.length, 1);

  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: signFor(id, ts()) });
  assert.equal(r.status, 202);
  const other = generateKeyPairSync("ed25519");
  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: b64uEncode(nodeSign(null, utf8(`jnex-device-token|${id}|${ts()}`), other.privateKey)) });
  assert.equal(r.status, 401);
  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: signFor("another-id", ts()) });
  assert.equal(r.status, 401);
  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts() - 1000, sig: signFor(id, ts() - 1000) });
  assert.equal(r.data.error.code, "stale_request");

  r = await c.admin("GET", "/v1/admin/devices?status=pending");
  assert.equal(r.data.devices.length, 1);
  assert.equal(r.data.devices[0].tenantName, "Test Mart");
  assert.equal((await c.call("POST", `/v1/admin/devices/${id}/approve`, {})).status, 401);
  r = await c.admin("POST", `/v1/admin/devices/${id}/approve`, {});
  assert.equal(r.data.device.deviceCode, "A");

  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: signFor(id, ts()) });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, "active");
  assert.equal(r.data.deviceCode, "A");
  const lic = await verifyLicense(r.data.license, env.LICENSE_PUBLIC_KEY);
  assert.ok(lic, "licence verifies with the public key (as the POS app will do offline)");
  assert.equal(lic!.tid, tenant.id);
  assert.equal(lic!.did, id);
  assert.equal(lic!.code, "A");
  assert.equal(lic!.grace, 14);
  assert.equal(lic!.exp, Math.floor(Date.parse(tenant.licenseExpiresAt) / 1000));
  const sig = r.data.license.split(".")[1];
  assert.equal(await verifyLicense(`${b64uEncode(utf8(JSON.stringify({ ...lic, plan: "enterprise" })))}.${sig}`, env.LICENSE_PUBLIC_KEY), null, "edited licence is rejected");

  const token = r.data.accessToken;
  assert.equal((await c.call("GET", "/v1/device/ping")).status, 401);
  r = await c.call("GET", "/v1/device/ping", undefined, { authorization: `Bearer ${token}`, "x-app-version": "1.7.0" });
  assert.equal(r.status, 200);
  assert.equal(repo.devices[0].appVersion, "1.7.0");
  assert.ok(repo.devices[0].lastSeenAt);
  clock.ms += 16 * 60 * 1000;
  assert.equal((await c.call("GET", "/v1/device/ping", undefined, { authorization: `Bearer ${token}` })).status, 401);

  const dev2 = generateKeyPairSync("ed25519");
  const pk2 = b64uEncode(Buffer.from(String(dev2.publicKey.export({ format: "jwk" }).x), "base64url"));
  const d2 = (await c.call("POST", "/v1/devices/register", { shopCode: tenant.code, name: "Counter 2", hwHash: "b".repeat(32), publicKey: pk2 })).data.device;
  assert.equal((await c.admin("POST", `/v1/admin/devices/${d2.id}/approve`, {})).data.device.deviceCode, "B");

  clock.ms += 1000;
  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: signFor(id, ts()) });
  const token2 = r.data.accessToken;
  assert.equal((await c.admin("POST", `/v1/admin/devices/${id}/revoke`, { reason: "PC replaced" })).data.device.status, "revoked");
  assert.equal((await c.call("GET", "/v1/device/ping", undefined, { authorization: `Bearer ${token2}` })).status, 403);
  r = await c.call("POST", `/v1/devices/${id}/token`, { ts: ts(), sig: signFor(id, ts()) });
  assert.equal(r.status, 403);
  assert.equal(r.data.error.code, "device_revoked");
  assert.ok(repo.audits.some((a) => a.action === "device.approved"));
  assert.ok(repo.audits.some((a) => a.action === "device.revoked"));
});

test("licence: extend, expiry blocks tokens, suspended shop blocks logins", async () => {
  const { repo, clock, c } = fresh();
  const { tenant, temp } = await shopWithOwner(c);
  const dev = generateKeyPairSync("ed25519");
  const publicKey = b64uEncode(Buffer.from(String(dev.publicKey.export({ format: "jwk" }).x), "base64url"));
  const id = (await c.call("POST", "/v1/devices/register", { shopCode: tenant.code, name: "C1", hwHash: "c".repeat(32), publicKey })).data.device.id;
  await c.admin("POST", `/v1/admin/devices/${id}/approve`, {});
  const tok = () => { const ts = Math.floor(clock.ms / 1000); return c.call("POST", `/v1/devices/${id}/token`, { ts, sig: b64uEncode(nodeSign(null, utf8(`jnex-device-token|${id}|${ts}`), dev.privateKey)) }); };
  assert.equal((await tok()).status, 200);
  clock.ms += 31 * 86400000;
  let r = await tok();
  assert.equal(r.status, 402);
  assert.equal(r.data.error.code, "license_expired");
  r = await c.admin("POST", `/v1/admin/tenants/${tenant.id}/license`, { days: 365 });
  assert.ok(Date.parse(r.data.licenseExpiresAt) > clock.ms + 360 * 86400000);
  assert.equal((await tok()).status, 200);
  const before = Date.parse(repo.tenants[0].licenseExpiresAt!);
  await c.admin("POST", `/v1/admin/tenants/${tenant.id}/license`, { days: 30 });
  assert.equal(Date.parse(repo.tenants[0].licenseExpiresAt!), before + 30 * 86400000);
  assert.equal((await c.admin("POST", `/v1/admin/tenants/${tenant.id}/license`, { days: 0 })).status, 400);

  repo.tenants[0].status = "suspended";
  assert.equal((await tok()).status, 403);
  assert.equal((await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: temp })).data.error.code, "account_suspended");
});

test("admin can reset a locked-out owner (authenticator / password)", async () => {
  const { repo, clock, c } = fresh();
  const { temp } = await shopWithOwner(c);
  const l = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: temp });
  const secret = (await c.call("POST", "/v1/auth/mfa/setup", { challenge: l.data.challenge })).data.secret;
  await c.call("POST", "/v1/auth/mfa/enable", { challenge: l.data.challenge, code: await totpCode(secret, clock.ms) });
  const owner = repo.owners[0];
  assert.equal(owner.mfaEnabled, true);
  const keep = c.cookie;
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 200);

  assert.equal((await c.admin("POST", `/v1/admin/owners/${owner.id}/reset`, {})).status, 400);
  const r = await c.admin("POST", `/v1/admin/owners/${owner.id}/reset`, { mfa: true, password: true });
  assert.equal(r.data.mfaReset, true);
  assert.match(r.data.temporaryPassword, /^[A-Za-z0-9]{14}$/);
  assert.equal(owner.mfaEnabled, false);
  assert.equal(owner.mustChangePassword, true);
  c.cookie = keep;
  assert.equal((await c.call("GET", "/v1/auth/session")).status, 401, "old sessions are signed out");
  const again = await c.call("POST", "/v1/auth/login", { email: "owner@test.lk", password: r.data.temporaryPassword });
  assert.equal(again.data.status, "mfa_setup_required");
  assert.equal((await c.admin("GET", `/v1/admin/tenants/${owner.tenantId}/owners`)).data.owners[0].email, "owner@test.lk"); // emails are stored in lower case
});

test("admin page is served with a strict content-security-policy", async () => {
  const { c } = fresh();
  const r = await c.call("GET", "/admin");
  assert.equal(r.status, 200);
  const csp = r.headers.get("content-security-policy")!;
  assert.match(csp, /script-src 'nonce-[\w-]+'/);
  const nonce = /script-src 'nonce-([\w-]+)'/.exec(csp)![1];
  assert.ok((r.data as string).includes(`<script nonce="${nonce}">`));
  assert.match(csp, /frame-ancestors 'none'/);
});

test("duplicate owner email is refused; bad owner/shop input is rejected", async () => {
  const { c } = fresh();
  const { tenant } = await shopWithOwner(c);
  let r = await c.admin("POST", `/v1/admin/tenants/${tenant.id}/owners`, { email: "owner@test.lk", name: "Again" });
  assert.equal(r.status, 409);
  r = await c.admin("POST", `/v1/admin/tenants/${tenant.id}/owners`, { email: "not-an-email", name: "Bad" });
  assert.equal(r.status, 400);
  r = await c.admin("POST", "/v1/admin/tenants", { name: "x" });
  assert.equal(r.status, 400);
});
