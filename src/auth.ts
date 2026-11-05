// Owner (shop owner) login: email + password, then a 6-digit authenticator code.
// Used by the JnexHub dashboard.
import type { Ctx, Owner, SessionRow, Tenant } from "./types";
import { HttpError, SESSION_COOKIE, clearSessionCookie, email as emailField, json, parseCookies, readJson, sessionCookie, str } from "./http";
import { decryptString, encryptString, randomToken, sha256Hex } from "./crypto";
import { generateTotpSecret, otpauthUri, verifyTotp } from "./totp";

const SESSION_TTL_MS = 12 * 3600 * 1000; // idle window, renewed while in use
const SESSION_MAX_MS = 7 * 24 * 3600 * 1000; // hard limit from login
const CHALLENGE_TTL_MS = 10 * 60 * 1000;
const MAX_CODE_TRIES = 5;

const iso = (ms: number): string => new Date(ms).toISOString();

export function checkPasswordPolicy(password: string, owner: { email: string }): void {
  const bytes = new TextEncoder().encode(password).length;
  if (password.length < 10) throw new HttpError(400, "weak_password", "Password must be at least 10 characters.");
  if (bytes > 72) throw new HttpError(400, "weak_password", "Password is too long (max 72 bytes).");
  if (password.toLowerCase() === owner.email.toLowerCase()) throw new HttpError(400, "weak_password", "Password cannot be your email.");
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) throw new HttpError(400, "weak_password", "Use letters and numbers in the password.");
}

function ownerPayload(owner: Owner, tenant: Tenant | null) {
  return {
    id: owner.id,
    email: owner.email,
    name: owner.name,
    tenantId: owner.tenantId,
    shopName: tenant?.name ?? null,
    licenseExpiresAt: tenant?.licenseExpiresAt ?? null,
    mustChangePassword: owner.mustChangePassword,
  };
}

async function issueSession(ctx: Ctx, owner: Owner): Promise<Response> {
  const token = randomToken(32);
  const nowMs = ctx.now().getTime();
  await ctx.repo.createSession({
    ownerId: owner.id,
    tokenHash: await sha256Hex(token),
    expiresAt: iso(nowMs + SESSION_TTL_MS),
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });
  await ctx.repo.touchLogin(owner.id);
  await ctx.repo.audit({ tenantId: owner.tenantId, actor: `owner:${owner.id}`, action: "owner.login", details: { ip: ctx.ip } });
  const tenant = await ctx.repo.getTenant(owner.tenantId);
  return json({ status: "ok", owner: ownerPayload(owner, tenant) }, 200, {
    "set-cookie": sessionCookie(ctx, token, Math.floor(SESSION_TTL_MS / 1000)),
  });
}

export interface AuthedSession {
  owner: Owner;
  tenant: Tenant | null;
  session: SessionRow;
}

// Checks the session cookie. Owners who still have a temporary password may
// only use the "change password" / "logout" endpoints (allowMustChange).
export async function requireSession(ctx: Ctx, opts: { allowMustChange?: boolean } = {}): Promise<AuthedSession> {
  const token = parseCookies(ctx.req.headers.get("cookie"))[SESSION_COOKIE];
  if (!token) throw new HttpError(401, "not_signed_in", "Please sign in.");
  const session = await ctx.repo.getSessionByHash(await sha256Hex(token));
  const nowMs = ctx.now().getTime();
  if (!session || session.revokedAt || Date.parse(session.expiresAt) <= nowMs || Date.parse(session.createdAt) + SESSION_MAX_MS <= nowMs) {
    throw new HttpError(401, "session_expired", "Your session has expired. Please sign in again.");
  }
  const owner = await ctx.repo.getOwner(session.ownerId);
  if (!owner || owner.status !== "active") throw new HttpError(401, "session_expired", "Your session has expired. Please sign in again.");
  if (owner.mustChangePassword && !opts.allowMustChange) {
    throw new HttpError(403, "password_change_required", "Please change your temporary password first.");
  }
  // slide the idle window forward once half of it has been used
  if (Date.parse(session.expiresAt) - nowMs < SESSION_TTL_MS / 2) {
    await ctx.repo.touchSession(session.id, iso(Math.min(nowMs + SESSION_TTL_MS, Date.parse(session.createdAt) + SESSION_MAX_MS)));
  }
  return { owner, tenant: await ctx.repo.getTenant(owner.tenantId), session };
}

// ---- 1. password -----------------------------------------------------------
export async function login(ctx: Ctx): Promise<Response> {
  const body = await readJson(ctx.req);
  const email = emailField(body.email);
  const password = str(body.password, "password", 1, 200);

  const ipKey = `login-ip:${ctx.ip}`;
  const emailKey = `login-email:${email}`;
  if ((await ctx.repo.rateCount(ipKey, 600)) >= 30 || (await ctx.repo.rateCount(emailKey, 300)) >= 5) {
    throw new HttpError(429, "too_many_attempts", "Too many attempts. Please wait 5 minutes and try again.", { retryAfter: 300 });
  }

  const owner = await ctx.repo.findOwnerByEmail(email);
  let ok = false;
  if (owner && owner.status === "active") ok = await ctx.repo.verifyOwnerPassword(owner.id, password);
  else await ctx.repo.fakePasswordCheck(password); // same time whether or not the email exists
  if (!ok || !owner) {
    await ctx.repo.rateHit(ipKey, 600);
    await ctx.repo.rateHit(emailKey, 300);
    throw new HttpError(401, "invalid_credentials", "Wrong email or password.");
  }

  const tenant = await ctx.repo.getTenant(owner.tenantId);
  if (!tenant || tenant.status !== "active") throw new HttpError(403, "account_suspended", "This account is suspended. Please contact Jnex support.");

  const kind = owner.mfaEnabled ? "mfa" : "mfa_setup";
  const challenge = randomToken(32);
  await ctx.repo.createChallenge({ ownerId: owner.id, kind, tokenHash: await sha256Hex(challenge), expiresAt: iso(ctx.now().getTime() + CHALLENGE_TTL_MS) });
  return json({ status: owner.mfaEnabled ? "mfa_required" : "mfa_setup_required", challenge, mustChangePassword: owner.mustChangePassword });
}

async function loadChallenge(ctx: Ctx, token: unknown, kind: "mfa" | "mfa_setup") {
  const t = str(token, "challenge", 10, 200);
  const ch = await ctx.repo.getChallenge(await sha256Hex(t));
  if (!ch || ch.kind !== kind || Date.parse(ch.expiresAt) <= ctx.now().getTime()) {
    throw new HttpError(401, "challenge_invalid", "That sign-in step has expired. Please start again.");
  }
  const owner = await ctx.repo.getOwner(ch.ownerId);
  if (!owner || owner.status !== "active") throw new HttpError(401, "challenge_invalid", "That sign-in step has expired. Please start again.");
  return { ch, owner };
}

async function checkCode(ctx: Ctx, ch: { id: string }, owner: Owner, code: unknown): Promise<void> {
  const c = typeof code === "string" ? code.replace(/\s/g, "") : "";
  if (!owner.mfaSecretEnc) throw new HttpError(409, "mfa_not_ready", "Authenticator is not set up yet.");
  const secret = await decryptString(owner.mfaSecretEnc, ctx.env.DATA_KEY);
  const step = await verifyTotp(secret, c, ctx.now().getTime(), owner.mfaLastStep);
  if (step === null) {
    const tries = await ctx.repo.bumpChallengeAttempts(ch.id);
    if (tries >= MAX_CODE_TRIES) {
      await ctx.repo.deleteChallenge(ch.id);
      throw new HttpError(401, "challenge_invalid", "Too many wrong codes. Please sign in again.");
    }
    throw new HttpError(401, "invalid_code", "That code is not correct.");
  }
  await ctx.repo.setMfaLastStep(owner.id, step); // each code works once
}

// ---- 2a. first time: set up the authenticator app --------------------------
export async function mfaSetup(ctx: Ctx): Promise<Response> {
  const body = await readJson(ctx.req);
  const { owner } = await loadChallenge(ctx, body.challenge, "mfa_setup");
  if (owner.mfaEnabled) throw new HttpError(409, "mfa_already_on", "Authenticator is already set up.");
  const secret = generateTotpSecret();
  await ctx.repo.setOwnerMfa(owner.id, { secretEnc: await encryptString(secret, ctx.env.DATA_KEY), enabled: false });
  return json({ secret, otpauthUri: otpauthUri(owner.email, "Jnex", secret) });
}

export async function mfaEnable(ctx: Ctx): Promise<Response> {
  const body = await readJson(ctx.req);
  const { ch, owner } = await loadChallenge(ctx, body.challenge, "mfa_setup");
  await checkCode(ctx, ch, owner, body.code);
  await ctx.repo.setOwnerMfa(owner.id, { secretEnc: owner.mfaSecretEnc, enabled: true });
  await ctx.repo.deleteChallenge(ch.id);
  await ctx.repo.audit({ tenantId: owner.tenantId, actor: `owner:${owner.id}`, action: "owner.mfa_enabled" });
  return issueSession(ctx, { ...owner, mfaEnabled: true });
}

// ---- 2b. every later login: the 6-digit code ---------------------------------
export async function mfaVerify(ctx: Ctx): Promise<Response> {
  const body = await readJson(ctx.req);
  const { ch, owner } = await loadChallenge(ctx, body.challenge, "mfa");
  await checkCode(ctx, ch, owner, body.code);
  await ctx.repo.deleteChallenge(ch.id);
  return issueSession(ctx, owner);
}

// ---- session ----------------------------------------------------------------
export async function getSession(ctx: Ctx): Promise<Response> {
  const { owner, tenant } = await requireSession(ctx, { allowMustChange: true });
  return json({ owner: ownerPayload(owner, tenant), serverTime: ctx.now().toISOString() });
}

export async function logout(ctx: Ctx): Promise<Response> {
  try {
    const { owner, session } = await requireSession(ctx, { allowMustChange: true });
    await ctx.repo.revokeSession(owner.id, session.id);
  } catch {
    /* already signed out */
  }
  return json({ status: "ok" }, 200, { "set-cookie": clearSessionCookie(ctx) });
}

export async function logoutEverywhere(ctx: Ctx): Promise<Response> {
  const { owner } = await requireSession(ctx, { allowMustChange: true });
  await ctx.repo.revokeAllSessions(owner.id);
  await ctx.repo.audit({ tenantId: owner.tenantId, actor: `owner:${owner.id}`, action: "owner.logout_everywhere" });
  return json({ status: "ok" }, 200, { "set-cookie": clearSessionCookie(ctx) });
}

export async function listSessions(ctx: Ctx): Promise<Response> {
  const { owner, session } = await requireSession(ctx);
  const rows = await ctx.repo.listSessions(owner.id);
  return json({
    sessions: rows
      .filter((s) => !s.revokedAt && Date.parse(s.expiresAt) > ctx.now().getTime())
      .map((s) => ({ id: s.id, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, ip: s.ip, userAgent: s.userAgent, current: s.id === session.id })),
  });
}

export async function revokeSession(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  const { owner } = await requireSession(ctx);
  const ok = await ctx.repo.revokeSession(owner.id, params.id);
  if (!ok) throw new HttpError(404, "not_found", "Session not found.");
  return json({ status: "ok" });
}

export async function changePassword(ctx: Ctx): Promise<Response> {
  const { owner, session } = await requireSession(ctx, { allowMustChange: true });
  const body = await readJson(ctx.req);
  const current = str(body.current, "current password", 1, 200);
  const next = str(body.next, "new password", 1, 200);

  const key = `pw-change:${owner.id}`;
  if ((await ctx.repo.rateCount(key, 600)) >= 5) throw new HttpError(429, "too_many_attempts", "Too many attempts. Please wait a few minutes.", { retryAfter: 600 });
  if (!(await ctx.repo.verifyOwnerPassword(owner.id, current))) {
    await ctx.repo.rateHit(key, 600);
    throw new HttpError(401, "invalid_credentials", "Your current password is not correct.");
  }
  if (current === next) throw new HttpError(400, "weak_password", "The new password must be different.");
  checkPasswordPolicy(next, owner);

  await ctx.repo.setOwnerPassword(owner.id, next, false);
  await ctx.repo.revokeAllSessions(owner.id, session.id); // every other device is signed out
  await ctx.repo.audit({ tenantId: owner.tenantId, actor: `owner:${owner.id}`, action: "owner.password_changed" });
  return json({ status: "ok" });
}
