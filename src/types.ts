export interface Env {
  DATABASE_URL: string;
  ADMIN_API_KEY: string;
  JWT_SECRET: string;
  DATA_KEY: string; // 32 random bytes, base64
  LICENSE_PRIVATE_KEY: string; // Ed25519 PKCS8, base64
  LICENSE_PUBLIC_KEY: string; // Ed25519 raw public key, base64url
  ALLOWED_ORIGINS?: string;
  ENVIRONMENT?: string; // "dev" allows http cookies on localhost
}

export type DeviceStatus = "pending" | "active" | "revoked";

export interface Tenant {
  id: string;
  code: string;
  name: string;
  plan: string;
  status: "active" | "suspended";
  licenseExpiresAt: string | null;
  createdAt: string;
}
export interface TenantSummary extends Tenant {
  ownerCount: number;
  activeDevices: number;
  pendingDevices: number;
}
export interface Owner {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  mustChangePassword: boolean;
  mfaEnabled: boolean;
  mfaSecretEnc: string | null;
  mfaLastStep: number | null;
  status: "active" | "disabled";
  lastLoginAt: string | null;
}
export interface Device {
  id: string;
  tenantId: string;
  tenantName?: string;
  name: string;
  hwHash: string;
  publicKey: string; // Ed25519 raw, base64url
  status: DeviceStatus;
  deviceCode: string | null;
  appVersion: string | null;
  revokeReason: string | null;
  createdAt: string;
  approvedAt: string | null;
  revokedAt: string | null;
  lastSeenAt: string | null;
}
export interface Challenge {
  id: string;
  ownerId: string;
  kind: "mfa" | "mfa_setup";
  attempts: number;
  expiresAt: string;
}
export interface SessionRow {
  id: string;
  ownerId: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip: string | null;
  userAgent: string | null;
  revokedAt: string | null;
}

// Everything the handlers need from the database. PgRepo (Neon) is the real
// one; the tests use an in-memory copy.
export interface Repo {
  ping(): Promise<boolean>;
  purgeExpired(): Promise<void>;

  rateCount(key: string, windowSec: number): Promise<number>;
  rateHit(key: string, windowSec: number): Promise<number>;

  createTenant(t: { code: string; name: string; plan: string; licenseExpiresAt: string | null }): Promise<Tenant>;
  getTenant(id: string): Promise<Tenant | null>;
  getTenantByCode(code: string): Promise<Tenant | null>;
  listTenants(): Promise<TenantSummary[]>;
  setTenantLicense(id: string, expiresAt: string | null): Promise<void>;

  createOwner(o: { tenantId: string; email: string; name: string; password: string; mustChangePassword: boolean }): Promise<Owner>;
  findOwnerByEmail(email: string): Promise<Owner | null>;
  getOwner(id: string): Promise<Owner | null>;
  listOwners(tenantId: string): Promise<Owner[]>;
  verifyOwnerPassword(ownerId: string, password: string): Promise<boolean>;
  fakePasswordCheck(password: string): Promise<void>;
  setOwnerPassword(ownerId: string, password: string, mustChange: boolean): Promise<void>;
  setOwnerMfa(ownerId: string, v: { secretEnc: string | null; enabled: boolean }): Promise<void>;
  setMfaLastStep(ownerId: string, step: number): Promise<void>;
  touchLogin(ownerId: string): Promise<void>;

  createChallenge(c: { ownerId: string; kind: "mfa" | "mfa_setup"; tokenHash: string; expiresAt: string }): Promise<void>;
  getChallenge(tokenHash: string): Promise<Challenge | null>;
  bumpChallengeAttempts(id: string): Promise<number>;
  deleteChallenge(id: string): Promise<void>;

  createSession(s: { ownerId: string; tokenHash: string; expiresAt: string; ip: string | null; userAgent: string | null }): Promise<SessionRow>;
  getSessionByHash(tokenHash: string): Promise<SessionRow | null>;
  touchSession(id: string, expiresAt: string): Promise<void>;
  listSessions(ownerId: string): Promise<SessionRow[]>;
  revokeSession(ownerId: string, sessionId: string): Promise<boolean>;
  revokeAllSessions(ownerId: string, exceptId?: string): Promise<void>;

  createDevice(d: { tenantId: string; name: string; hwHash: string; publicKey: string; appVersion: string | null }): Promise<Device>;
  getDevice(id: string): Promise<Device | null>;
  findDeviceByKey(tenantId: string, publicKey: string): Promise<Device | null>;
  listDevices(f: { status?: DeviceStatus; tenantId?: string }): Promise<Device[]>;
  countDeviceCodes(tenantId: string): Promise<number>;
  approveDevice(id: string, code: string): Promise<Device | null>;
  revokeDevice(id: string, reason: string): Promise<Device | null>;
  touchDevice(id: string, appVersion: string | null): Promise<void>;

  audit(e: { tenantId?: string | null; actor: string; action: string; details?: Record<string, unknown> }): Promise<void>;
}

export interface Ctx {
  env: Env;
  repo: Repo;
  req: Request;
  url: URL;
  ip: string;
  userAgent: string | null;
  now: () => Date;
}
