// TOTP (RFC 6238): the 6-digit codes from Google Authenticator / Microsoft Authenticator.
import { randomBytes, utf8 } from "./crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("bad base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export const generateTotpSecret = (): string => base32Encode(randomBytes(20));

export function otpauthUri(account: string, issuer: string, secret: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export async function hotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 255;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg as BufferSource));
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export const totpStep = (nowMs: number, period = 30): number => Math.floor(nowMs / 1000 / period);

export async function totpCode(secretB32: string, nowMs: number, digits = 6): Promise<string> {
  return hotp(base32Decode(secretB32), totpStep(nowMs), digits);
}

// Returns the matching step (so it can be remembered) or null.
// Accepts one step either side (clock drift) and refuses a step that was already used.
export async function verifyTotp(secretB32: string, code: string, nowMs: number, lastUsedStep: number | null): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const secret = base32Decode(secretB32);
  const cur = totpStep(nowMs);
  for (const step of [cur, cur - 1, cur + 1]) {
    if (lastUsedStep !== null && step <= lastUsedStep) continue;
    if ((await hotp(secret, step)) === code) return step;
  }
  return null;
}
export { utf8 };
