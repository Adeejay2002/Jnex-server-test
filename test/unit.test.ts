import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { b64Encode, b64uDecode, b64uEncode, decryptString, ed25519Sign, ed25519Verify, encryptString, randomToken, safeEqualStrings, sha256Hex, signJwt, timingSafeEqual, utf8, verifyJwt } from "../src/crypto";
import { base32Decode, base32Encode, hotp, totpCode, verifyTotp } from "../src/totp";
import { deviceCodeFor } from "../src/devices";
import { newShopCode, temporaryPassword } from "../src/admin";

test("base64url round trip", () => {
  const b = new Uint8Array([0, 250, 251, 252, 253, 254, 255, 1, 2]);
  assert.deepEqual(b64uDecode(b64uEncode(b)), b);
  assert.ok(!/[+/=]/.test(b64uEncode(b)));
});

test("sha256 and constant-time compare", async () => {
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(timingSafeEqual(utf8("same"), utf8("same")), true);
  assert.equal(timingSafeEqual(utf8("same"), utf8("sbme")), false);
  assert.equal(await safeEqualStrings("a-long-secret", "a-long-secret"), true);
  assert.equal(await safeEqualStrings("a-long-secret", "a-long-secreT"), false);
  assert.notEqual(randomToken(), randomToken());
});

test("JWT: valid, tampered, expired, wrong secret", async () => {
  const now = 1_800_000_000;
  const t = await signJwt({ sub: "d1", exp: now + 60 }, "secret-1");
  assert.equal((await verifyJwt(t, "secret-1", now))?.sub, "d1");
  assert.equal(await verifyJwt(t, "secret-2", now), null);
  assert.equal(await verifyJwt(t, "secret-1", now + 61), null);
  const [h, , s] = t.split(".");
  const forged = `${h}.${b64uEncode(utf8(JSON.stringify({ sub: "admin", exp: now + 60 })))}.${s}`;
  assert.equal(await verifyJwt(forged, "secret-1", now), null);
  const none = `${b64uEncode(utf8('{"alg":"none"}'))}.${b64uEncode(utf8(JSON.stringify({ sub: "x", exp: now + 60 })))}.`;
  assert.equal(await verifyJwt(none, "secret-1", now), null);
});

test("AES-GCM: round trip and tamper detection", async () => {
  const key = b64Encode(crypto.getRandomValues(new Uint8Array(32)));
  const enc = await encryptString("JBSWY3DPEHPK3PXP", key);
  assert.equal(await decryptString(enc, key), "JBSWY3DPEHPK3PXP");
  assert.notEqual(enc, await encryptString("JBSWY3DPEHPK3PXP", key)); // new IV each time
  const parts = enc.split(".");
  const ct = b64uDecode(parts[2]);
  ct[0] ^= 1; // flip one bit
  parts[2] = b64uEncode(ct);
  await assert.rejects(decryptString(parts.join("."), key));
  await assert.rejects(encryptString("x", b64Encode(new Uint8Array(16)))); // key must be 32 bytes
});

test("Ed25519: sign / verify with the same encodings the server uses", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  const pub = String(publicKey.export({ format: "jwk" }).x);
  const msg = utf8("hello");
  const sig = await ed25519Sign(priv, msg);
  assert.equal(await ed25519Verify(pub, sig, msg), true);
  assert.equal(await ed25519Verify(pub, sig, utf8("hellO")), false);
  assert.equal(await ed25519Verify("AAAA", sig, msg), false);
});

test("TOTP matches the RFC 6238 test vectors (SHA-1)", async () => {
  const secret = base32Encode(utf8("12345678901234567890"));
  assert.equal(await totpCode(secret, 59 * 1000, 8), "94287082");
  assert.equal(await totpCode(secret, 1111111109 * 1000, 8), "07081804");
  assert.equal(await totpCode(secret, 1234567890 * 1000, 8), "89005924");
  assert.equal(await totpCode(secret, 2000000000 * 1000, 8), "69279037");
  assert.equal(await totpCode(secret, 59 * 1000), "287082");
  assert.deepEqual(base32Decode(secret), utf8("12345678901234567890"));
  assert.equal(await hotp(utf8("12345678901234567890"), 0), "755224"); // RFC 4226 vector
});

test("TOTP verification: drift window, wrong code, replay", async () => {
  const secret = base32Encode(utf8("12345678901234567890"));
  const now = 1_111_111_109_000;
  const code = await totpCode(secret, now);
  const step = await verifyTotp(secret, code, now, null);
  assert.equal(step, Math.floor(now / 30000));
  assert.equal(await verifyTotp(secret, code, now, step), null); // same code twice: refused
  assert.notEqual(await verifyTotp(secret, code, now + 30000, null), null); // one step late is fine
  assert.equal(await verifyTotp(secret, code, now + 90000, null), null); // 3 steps late is not
  assert.equal(await verifyTotp(secret, "000000", now, null), null);
  assert.equal(await verifyTotp(secret, "12345", now, null), null);
  assert.equal(await verifyTotp(secret, "abcdef", now, null), null);
});

test("machine letters and generated codes", () => {
  assert.deepEqual([0, 1, 25, 26, 27, 51, 52].map(deviceCodeFor), ["A", "B", "Z", "AA", "AB", "AZ", "BA"]);
  assert.match(newShopCode(), /^JX-[A-HJ-NP-Z2-9]{8}$/);
  for (let i = 0; i < 50; i++) assert.match(temporaryPassword(), /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{14}$/);
});
