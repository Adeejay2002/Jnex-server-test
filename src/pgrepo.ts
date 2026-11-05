// Real database access (Neon Postgres over HTTPS). One SQL statement per call.
// Passwords are hashed INSIDE Postgres (pgcrypto bcrypt) so the Worker's small CPU
// budget is not used for hashing, and the hash never leaves the database.
import { neon } from "@neondatabase/serverless";
import type { Challenge, Device, DeviceStatus, Owner, Repo, SessionRow, Tenant, TenantSummary } from "./types";
import { HttpError } from "./http";

type Row = Record<string, any>;
const iso = (v: any): string | null => (v == null ? null : new Date(v).toISOString());
const isoReq = (v: any): string => new Date(v).toISOString();

const toTenant = (r: Row): Tenant => ({
  id: r.id,
  code: r.code,
  name: r.name,
  plan: r.plan,
  status: r.status,
  licenseExpiresAt: iso(r.license_expires_at),
  createdAt: isoReq(r.created_at),
});
const toOwner = (r: Row): Owner => ({
  id: r.id,
  tenantId: r.tenant_id,
  email: r.email,
  name: r.name,
  mustChangePassword: r.must_change_password,
  mfaEnabled: r.mfa_enabled,
  mfaSecretEnc: r.mfa_secret_enc ?? null,
  mfaLastStep: r.mfa_last_step == null ? null : Number(r.mfa_last_step),
  status: r.status,
  lastLoginAt: iso(r.last_login_at),
});
const toDevice = (r: Row): Device => ({
  id: r.id,
  tenantId: r.tenant_id,
  tenantName: r.tenant_name ?? undefined,
  name: r.name,
  hwHash: r.hw_hash,
  publicKey: r.public_key,
  status: r.status as DeviceStatus,
  deviceCode: r.device_code ?? null,
  appVersion: r.app_version ?? null,
  revokeReason: r.revoke_reason ?? null,
  createdAt: isoReq(r.created_at),
  approvedAt: iso(r.approved_at),
  revokedAt: iso(r.revoked_at),
  lastSeenAt: iso(r.last_seen_at),
});
const toSession = (r: Row): SessionRow => ({
  id: r.id,
  ownerId: r.owner_id,
  createdAt: isoReq(r.created_at),
  lastSeenAt: isoReq(r.last_seen_at),
  expiresAt: isoReq(r.expires_at),
  ip: r.ip ?? null,
  userAgent: r.user_agent ?? null,
  revokedAt: iso(r.revoked_at),
});

export class PgRepo implements Repo {
  private sql: ReturnType<typeof neon>;
  constructor(connectionString: string) {
    this.sql = neon(connectionString);
  }

  private async q(text: string, params: unknown[] = []): Promise<Row[]> {
    try {
      return (await this.sql.query(text, params)) as Row[];
    } catch (e: any) {
      if (e && e.code === "23505") throw new HttpError(409, "conflict", "That already exists.");
      throw e;
    }
  }

  async ping(): Promise<boolean> {
    return (await this.q("SELECT 1 AS ok")).length === 1;
  }
  async purgeExpired(): Promise<void> {
    await this.q("DELETE FROM auth_challenges WHERE expires_at < now()");
    await this.q("DELETE FROM sessions WHERE expires_at < now() - interval '1 day' OR revoked_at < now() - interval '1 day'");
    await this.q("DELETE FROM rate_limits WHERE window_start < now() - interval '2 days'");
  }

  async rateCount(key: string, windowSec: number): Promise<number> {
    const r = await this.q(
      "SELECT COALESCE(sum(count), 0)::int AS n FROM rate_limits WHERE key = $1 AND window_start >= now() - ($2::int * interval '1 second')",
      [key, windowSec],
    );
    return r[0].n;
  }
  async rateHit(key: string, windowSec: number): Promise<number> {
    const r = await this.q(
      `INSERT INTO rate_limits (key, window_start, count)
       VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2::int) * $2::int), 1)
       ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1
       RETURNING count`,
      [key, windowSec],
    );
    return r[0].count;
  }

  async createTenant(t: { code: string; name: string; plan: string; licenseExpiresAt: string | null }): Promise<Tenant> {
    const r = await this.q("INSERT INTO tenants (code, name, plan, license_expires_at) VALUES ($1,$2,$3,$4) RETURNING *", [t.code, t.name, t.plan, t.licenseExpiresAt]);
    return toTenant(r[0]);
  }
  async getTenant(id: string): Promise<Tenant | null> {
    const r = await this.q("SELECT * FROM tenants WHERE id::text = $1", [id]);
    return r[0] ? toTenant(r[0]) : null;
  }
  async getTenantByCode(code: string): Promise<Tenant | null> {
    const r = await this.q("SELECT * FROM tenants WHERE code = $1", [code]);
    return r[0] ? toTenant(r[0]) : null;
  }
  async listTenants(): Promise<TenantSummary[]> {
    const r = await this.q(
      `SELECT t.*,
        (SELECT count(*) FROM owners o WHERE o.tenant_id = t.id)::int AS owner_count,
        (SELECT count(*) FROM devices d WHERE d.tenant_id = t.id AND d.status = 'active')::int AS active_devices,
        (SELECT count(*) FROM devices d WHERE d.tenant_id = t.id AND d.status = 'pending')::int AS pending_devices
       FROM tenants t ORDER BY t.created_at DESC`,
    );
    return r.map((x) => ({ ...toTenant(x), ownerCount: x.owner_count, activeDevices: x.active_devices, pendingDevices: x.pending_devices }));
  }
  async setTenantLicense(id: string, expiresAt: string | null): Promise<void> {
    await this.q("UPDATE tenants SET license_expires_at = $2 WHERE id::text = $1", [id, expiresAt]);
  }

  async createOwner(o: { tenantId: string; email: string; name: string; password: string; mustChangePassword: boolean }): Promise<Owner> {
    const r = await this.q(
      `INSERT INTO owners (tenant_id, email, name, password_hash, must_change_password)
       VALUES ($1, $2, $3, crypt($4, gen_salt('bf', 10)), $5) RETURNING *`,
      [o.tenantId, o.email, o.name, o.password, o.mustChangePassword],
    );
    return toOwner(r[0]);
  }
  async findOwnerByEmail(email: string): Promise<Owner | null> {
    const r = await this.q("SELECT * FROM owners WHERE email = $1", [email]);
    return r[0] ? toOwner(r[0]) : null;
  }
  async getOwner(id: string): Promise<Owner | null> {
    const r = await this.q("SELECT * FROM owners WHERE id::text = $1", [id]);
    return r[0] ? toOwner(r[0]) : null;
  }
  async listOwners(tenantId: string): Promise<Owner[]> {
    return (await this.q("SELECT * FROM owners WHERE tenant_id::text = $1 ORDER BY created_at", [tenantId])).map(toOwner);
  }
  async verifyOwnerPassword(ownerId: string, password: string): Promise<boolean> {
    const r = await this.q("SELECT (password_hash = crypt($2, password_hash)) AS ok FROM owners WHERE id::text = $1", [ownerId, password]);
    return r[0]?.ok === true;
  }
  async fakePasswordCheck(password: string): Promise<void> {
    await this.q("SELECT crypt($1, '$2a$10$N9qo8uLOickgx2ZMRZoMye') AS x", [password]);
  }
  async setOwnerPassword(ownerId: string, password: string, mustChange: boolean): Promise<void> {
    await this.q("UPDATE owners SET password_hash = crypt($2, gen_salt('bf', 10)), must_change_password = $3 WHERE id::text = $1", [ownerId, password, mustChange]);
  }
  async setOwnerMfa(ownerId: string, v: { secretEnc: string | null; enabled: boolean }): Promise<void> {
    await this.q("UPDATE owners SET mfa_secret_enc = $2, mfa_enabled = $3, mfa_last_step = NULL WHERE id::text = $1", [ownerId, v.secretEnc, v.enabled]);
  }
  async setMfaLastStep(ownerId: string, step: number): Promise<void> {
    await this.q("UPDATE owners SET mfa_last_step = $2 WHERE id::text = $1", [ownerId, step]);
  }
  async touchLogin(ownerId: string): Promise<void> {
    await this.q("UPDATE owners SET last_login_at = now() WHERE id::text = $1", [ownerId]);
  }

  async createChallenge(c: { ownerId: string; kind: "mfa" | "mfa_setup"; tokenHash: string; expiresAt: string }): Promise<void> {
    await this.q("INSERT INTO auth_challenges (owner_id, kind, token_hash, expires_at) VALUES ($1,$2,$3,$4)", [c.ownerId, c.kind, c.tokenHash, c.expiresAt]);
  }
  async getChallenge(tokenHash: string): Promise<Challenge | null> {
    const r = await this.q("SELECT * FROM auth_challenges WHERE token_hash = $1", [tokenHash]);
    return r[0] ? { id: r[0].id, ownerId: r[0].owner_id, kind: r[0].kind, attempts: r[0].attempts, expiresAt: isoReq(r[0].expires_at) } : null;
  }
  async bumpChallengeAttempts(id: string): Promise<number> {
    const r = await this.q("UPDATE auth_challenges SET attempts = attempts + 1 WHERE id::text = $1 RETURNING attempts", [id]);
    return r[0]?.attempts ?? 99;
  }
  async deleteChallenge(id: string): Promise<void> {
    await this.q("DELETE FROM auth_challenges WHERE id::text = $1", [id]);
  }

  async createSession(s: { ownerId: string; tokenHash: string; expiresAt: string; ip: string | null; userAgent: string | null }): Promise<SessionRow> {
    const r = await this.q("INSERT INTO sessions (owner_id, token_hash, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4,$5) RETURNING *", [
      s.ownerId,
      s.tokenHash,
      s.expiresAt,
      s.ip,
      s.userAgent,
    ]);
    return toSession(r[0]);
  }
  async getSessionByHash(tokenHash: string): Promise<SessionRow | null> {
    const r = await this.q("SELECT * FROM sessions WHERE token_hash = $1", [tokenHash]);
    return r[0] ? toSession(r[0]) : null;
  }
  async touchSession(id: string, expiresAt: string): Promise<void> {
    await this.q("UPDATE sessions SET last_seen_at = now(), expires_at = $2 WHERE id::text = $1", [id, expiresAt]);
  }
  async listSessions(ownerId: string): Promise<SessionRow[]> {
    return (await this.q("SELECT * FROM sessions WHERE owner_id::text = $1 ORDER BY created_at DESC LIMIT 50", [ownerId])).map(toSession);
  }
  async revokeSession(ownerId: string, sessionId: string): Promise<boolean> {
    const r = await this.q("UPDATE sessions SET revoked_at = now() WHERE id::text = $2 AND owner_id::text = $1 AND revoked_at IS NULL RETURNING id", [ownerId, sessionId]);
    return r.length === 1;
  }
  async revokeAllSessions(ownerId: string, exceptId?: string): Promise<void> {
    if (exceptId) await this.q("UPDATE sessions SET revoked_at = now() WHERE owner_id::text = $1 AND id::text <> $2 AND revoked_at IS NULL", [ownerId, exceptId]);
    else await this.q("UPDATE sessions SET revoked_at = now() WHERE owner_id::text = $1 AND revoked_at IS NULL", [ownerId]);
  }

  async createDevice(d: { tenantId: string; name: string; hwHash: string; publicKey: string; appVersion: string | null }): Promise<Device> {
    const r = await this.q("INSERT INTO devices (tenant_id, name, hw_hash, public_key, app_version) VALUES ($1,$2,$3,$4,$5) RETURNING *", [
      d.tenantId,
      d.name,
      d.hwHash,
      d.publicKey,
      d.appVersion,
    ]);
    return toDevice(r[0]);
  }
  async getDevice(id: string): Promise<Device | null> {
    const r = await this.q("SELECT * FROM devices WHERE id::text = $1", [id]);
    return r[0] ? toDevice(r[0]) : null;
  }
  async findDeviceByKey(tenantId: string, publicKey: string): Promise<Device | null> {
    const r = await this.q("SELECT * FROM devices WHERE tenant_id::text = $1 AND public_key = $2", [tenantId, publicKey]);
    return r[0] ? toDevice(r[0]) : null;
  }
  async listDevices(f: { status?: DeviceStatus; tenantId?: string }): Promise<Device[]> {
    const r = await this.q(
      `SELECT d.*, t.name AS tenant_name FROM devices d JOIN tenants t ON t.id = d.tenant_id
       WHERE ($1::text IS NULL OR d.status = $1::text) AND ($2::text IS NULL OR d.tenant_id::text = $2::text)
       ORDER BY d.created_at DESC LIMIT 500`,
      [f.status ?? null, f.tenantId ?? null],
    );
    return r.map(toDevice);
  }
  async countDeviceCodes(tenantId: string): Promise<number> {
    const r = await this.q("SELECT count(*)::int AS n FROM devices WHERE tenant_id::text = $1 AND device_code IS NOT NULL", [tenantId]);
    return r[0].n;
  }
  async approveDevice(id: string, code: string): Promise<Device | null> {
    const r = await this.q(
      `UPDATE devices SET status = 'active', approved_at = now(), revoked_at = NULL, revoke_reason = NULL,
         device_code = COALESCE(device_code, $2)
       WHERE id::text = $1 RETURNING *`,
      [id, code],
    );
    return r[0] ? toDevice(r[0]) : null;
  }
  async revokeDevice(id: string, reason: string): Promise<Device | null> {
    const r = await this.q("UPDATE devices SET status = 'revoked', revoked_at = now(), revoke_reason = $2 WHERE id::text = $1 RETURNING *", [id, reason]);
    return r[0] ? toDevice(r[0]) : null;
  }
  async touchDevice(id: string, appVersion: string | null): Promise<void> {
    await this.q("UPDATE devices SET last_seen_at = now(), app_version = COALESCE($2, app_version) WHERE id::text = $1", [id, appVersion]);
  }

  async audit(e: { tenantId?: string | null; actor: string; action: string; details?: Record<string, unknown> }): Promise<void> {
    await this.q("INSERT INTO audit_events (tenant_id, actor, action, details) VALUES ($1::uuid,$2,$3,$4::jsonb)", [e.tenantId ?? null, e.actor, e.action, JSON.stringify(e.details ?? {})]);
  }
}
