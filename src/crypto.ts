// Small helpers on top of Web Crypto (works in Cloudflare Workers and Node 20+).

const te = new TextEncoder();
const td = new TextDecoder();

export const utf8 = (s: string): Uint8Array => te.encode(s);
export const fromUtf8 = (b: Uint8Array): string => td.decode(b);

export function b64Encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
export function b64Decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64uEncode(bytes: Uint8Array): string {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(s: string): Uint8Array {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  return b64Decode(p + "=".repeat((4 - (p.length % 4)) % 4));
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
export const randomToken = (bytes = 32): string => b64uEncode(randomBytes(bytes));

export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  return Array.from(await sha256(data), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
// compares two secrets without leaking their length or where they differ
export async function safeEqualStrings(a: string, b: string): Promise<boolean> {
  return timingSafeEqual(await sha256(a), await sha256(b));
}

// ---- HS256 tokens (device access tokens) ---------------------------------
async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", utf8(secret) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
export async function signJwt(payload: Record<string, unknown>, secret: string): Promise<string> {
  const head = b64uEncode(utf8(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64uEncode(utf8(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), utf8(`${head}.${body}`) as BufferSource));
  return `${head}.${body}.${b64uEncode(sig)}`;
}
export async function verifyJwt(token: string, secret: string, nowSec: number): Promise<Record<string, any> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), b64uDecode(parts[2]) as BufferSource, utf8(`${parts[0]}.${parts[1]}`) as BufferSource);
    if (!ok) return null;
    const head = JSON.parse(fromUtf8(b64uDecode(parts[0])));
    if (head.alg !== "HS256") return null;
    const payload = JSON.parse(fromUtf8(b64uDecode(parts[1])));
    if (typeof payload.exp !== "number" || payload.exp <= nowSec) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---- AES-GCM (MFA secrets at rest) -----------------------------------------
async function aesKey(dataKeyB64: string): Promise<CryptoKey> {
  const raw = b64Decode(dataKeyB64);
  if (raw.length !== 32) throw new Error("DATA_KEY must be 32 bytes (base64)");
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function encryptString(plain: string, dataKeyB64: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, await aesKey(dataKeyB64), utf8(plain) as BufferSource));
  return `v1.${b64uEncode(iv)}.${b64uEncode(ct)}`;
}
export async function decryptString(enc: string, dataKeyB64: string): Promise<string> {
  const [v, iv, ct] = enc.split(".");
  if (v !== "v1" || !iv || !ct) throw new Error("bad ciphertext");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64uDecode(iv) as BufferSource }, await aesKey(dataKeyB64), b64uDecode(ct) as BufferSource);
  return fromUtf8(new Uint8Array(pt));
}

// ---- Ed25519 (licence tokens, device signatures) ----------------------------
// Standard name is "Ed25519"; older Workers runtimes call it "NODE-ED25519".
type EdAlg = { name: string; namedCurve?: string };
const ED_ALGS: EdAlg[] = [{ name: "Ed25519" }, { name: "NODE-ED25519", namedCurve: "NODE-ED25519" }];

interface EdKey {
  key: CryptoKey;
  alg: EdAlg;
}
async function importEd(format: "pkcs8" | "raw", bytes: Uint8Array, usage: "sign" | "verify"): Promise<EdKey> {
  let lastErr: unknown;
  for (const alg of ED_ALGS) {
    try {
      const key = await crypto.subtle.importKey(format, bytes as BufferSource, alg as any, false, [usage]);
      return { key, alg };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}
const privCache = new Map<string, EdKey>();
export async function ed25519Sign(privateKeyPkcs8B64: string, data: Uint8Array): Promise<Uint8Array> {
  let k = privCache.get(privateKeyPkcs8B64);
  if (!k) {
    k = await importEd("pkcs8", b64Decode(privateKeyPkcs8B64), "sign");
    privCache.set(privateKeyPkcs8B64, k);
  }
  return new Uint8Array(await crypto.subtle.sign(k.alg as any, k.key, data as BufferSource));
}
export async function ed25519Verify(publicKeyRawB64u: string, sig: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const raw = b64uDecode(publicKeyRawB64u);
    if (raw.length !== 32) return false;
    const k = await importEd("raw", raw, "verify");
    return await crypto.subtle.verify(k.alg as any, k.key, sig as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}
