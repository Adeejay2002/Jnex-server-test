// In-memory copy of the database layer, used only by the tests.
import { HttpError } from "../src/http";
import type { Challenge, Device, DeviceStatus, Owner, Repo, SessionRow, Tenant, TenantSummary } from "../src/types";

let n = 0;
const uid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;

export class MemRepo implements Repo {
  tenants: Tenant[] = [];
  owners: (Owner & { pw: string })[] = [];
  challenges: (Challenge & { tokenHash: string })[] = [];
  sessions: (SessionRow & { tokenHash: string })[] = [];
  devices: Device[] = [];
  rates = new Map<string, number>();
  audits: { actor: string; action: string; tenantId?: string | null; details?: Record<string, unknown> }[] = [];
  clock: () => number = () => Date.now();

  async ping() { return true; }
  async purgeExpired() {}
  async rateCount(key: string) { return this.rates.get(key) ?? 0; }
  async rateHit(key: string) { const v = (this.rates.get(key) ?? 0) + 1; this.rates.set(key, v); return v; }

  async createTenant(t: { code: string; name: string; plan: string; licenseExpiresAt: string | null }) {
    if (this.tenants.some((x) => x.code === t.code)) throw new HttpError(409, "conflict", "exists");
    const row: Tenant = { id: uid(), code: t.code, name: t.name, plan: t.plan, status: "active", licenseExpiresAt: t.licenseExpiresAt, createdAt: new Date(this.clock()).toISOString() };
    this.tenants.push(row);
    return row;
  }
  async getTenant(id: string) { return this.tenants.find((t) => t.id === id) ?? null; }
  async getTenantByCode(code: string) { return this.tenants.find((t) => t.code === code) ?? null; }
  async listTenants(): Promise<TenantSummary[]> {
    return this.tenants.map((t) => ({
      ...t,
      ownerCount: this.owners.filter((o) => o.tenantId === t.id).length,
      activeDevices: this.devices.filter((d) => d.tenantId === t.id && d.status === "active").length,
      pendingDevices: this.devices.filter((d) => d.tenantId === t.id && d.status === "pending").length,
    }));
  }
  async setTenantLicense(id: string, expiresAt: string | null) { const t = this.tenants.find((x) => x.id === id); if (t) t.licenseExpiresAt = expiresAt; }

  async createOwner(o: { tenantId: string; email: string; name: string; password: string; mustChangePassword: boolean }) {
    if (this.owners.some((x) => x.email.toLowerCase() === o.email.toLowerCase())) throw new HttpError(409, "conflict", "exists");
    const row = { id: uid(), tenantId: o.tenantId, email: o.email, name: o.name, mustChangePassword: o.mustChangePassword, mfaEnabled: false, mfaSecretEnc: null, mfaLastStep: null, status: "active" as const, lastLoginAt: null, pw: o.password };
    this.owners.push(row);
    return row;
  }
  async findOwnerByEmail(email: string) { return this.owners.find((o) => o.email.toLowerCase() === email.toLowerCase()) ?? null; }
  async getOwner(id: string) { return this.owners.find((o) => o.id === id) ?? null; }
  async listOwners(tenantId: string) { return this.owners.filter((o) => o.tenantId === tenantId); }
  async verifyOwnerPassword(id: string, password: string) { return this.owners.find((o) => o.id === id)?.pw === password; }
  async fakePasswordCheck() {}
  async setOwnerPassword(id: string, password: string, mustChange: boolean) { const o = this.owners.find((x) => x.id === id)!; o.pw = password; o.mustChangePassword = mustChange; }
  async setOwnerMfa(id: string, v: { secretEnc: string | null; enabled: boolean }) { const o = this.owners.find((x) => x.id === id)!; o.mfaSecretEnc = v.secretEnc; o.mfaEnabled = v.enabled; o.mfaLastStep = null; }
  async setMfaLastStep(id: string, step: number) { this.owners.find((x) => x.id === id)!.mfaLastStep = step; }
  async touchLogin(id: string) { this.owners.find((x) => x.id === id)!.lastLoginAt = new Date(this.clock()).toISOString(); }

  async createChallenge(c: { ownerId: string; kind: "mfa" | "mfa_setup"; tokenHash: string; expiresAt: string }) { this.challenges.push({ id: uid(), attempts: 0, ...c }); }
  async getChallenge(tokenHash: string) { return this.challenges.find((c) => c.tokenHash === tokenHash) ?? null; }
  async bumpChallengeAttempts(id: string) { const c = this.challenges.find((x) => x.id === id)!; return ++c.attempts; }
  async deleteChallenge(id: string) { this.challenges = this.challenges.filter((c) => c.id !== id); }

  async createSession(s: { ownerId: string; tokenHash: string; expiresAt: string; ip: string | null; userAgent: string | null }) {
    const now = new Date(this.clock()).toISOString();
    const row = { id: uid(), createdAt: now, lastSeenAt: now, revokedAt: null, ...s };
    this.sessions.push(row);
    return row;
  }
  async getSessionByHash(h: string) { return this.sessions.find((s) => s.tokenHash === h) ?? null; }
  async touchSession(id: string, expiresAt: string) { const s = this.sessions.find((x) => x.id === id)!; s.expiresAt = expiresAt; s.lastSeenAt = new Date(this.clock()).toISOString(); }
  async listSessions(ownerId: string) { return this.sessions.filter((s) => s.ownerId === ownerId); }
  async revokeSession(ownerId: string, id: string) { const s = this.sessions.find((x) => x.id === id && x.ownerId === ownerId && !x.revokedAt); if (!s) return false; s.revokedAt = new Date(this.clock()).toISOString(); return true; }
  async revokeAllSessions(ownerId: string, exceptId?: string) { for (const s of this.sessions) if (s.ownerId === ownerId && s.id !== exceptId && !s.revokedAt) s.revokedAt = new Date(this.clock()).toISOString(); }

  async createDevice(d: { tenantId: string; name: string; hwHash: string; publicKey: string; appVersion: string | null }) {
    const row: Device = { id: uid(), ...d, status: "pending", deviceCode: null, revokeReason: null, createdAt: new Date(this.clock()).toISOString(), approvedAt: null, revokedAt: null, lastSeenAt: null };
    this.devices.push(row);
    return row;
  }
  async getDevice(id: string) { return this.devices.find((d) => d.id === id) ?? null; }
  async findDeviceByKey(tenantId: string, k: string) { return this.devices.find((d) => d.tenantId === tenantId && d.publicKey === k) ?? null; }
  async listDevices(f: { status?: DeviceStatus; tenantId?: string }) {
    return this.devices
      .filter((d) => (!f.status || d.status === f.status) && (!f.tenantId || d.tenantId === f.tenantId))
      .map((d) => ({ ...d, tenantName: this.tenants.find((t) => t.id === d.tenantId)?.name }));
  }
  async countDeviceCodes(tenantId: string) { return this.devices.filter((d) => d.tenantId === tenantId && d.deviceCode).length; }
  async approveDevice(id: string, code: string) {
    const d = this.devices.find((x) => x.id === id);
    if (!d) return null;
    if (this.devices.some((x) => x.tenantId === d.tenantId && x.deviceCode === code && x.id !== id)) throw new HttpError(409, "conflict", "exists");
    d.status = "active"; d.approvedAt = new Date(this.clock()).toISOString(); d.revokedAt = null; d.revokeReason = null; d.deviceCode = d.deviceCode ?? code;
    return d;
  }
  async revokeDevice(id: string, reason: string) { const d = this.devices.find((x) => x.id === id); if (!d) return null; d.status = "revoked"; d.revokedAt = new Date(this.clock()).toISOString(); d.revokeReason = reason; return d; }
  async touchDevice(id: string, v: string | null) { const d = this.devices.find((x) => x.id === id)!; d.lastSeenAt = new Date(this.clock()).toISOString(); if (v) d.appVersion = v; }

  async audit(e: { tenantId?: string | null; actor: string; action: string; details?: Record<string, unknown> }) { this.audits.push(e); }
}
