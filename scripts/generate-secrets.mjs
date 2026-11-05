// Prints the random secrets the server needs. Run once:  npm run secrets
// Copy each value into Cloudflare (Settings > Variables and Secrets, type "Secret") and into
// your local ".dev.vars". Keep them private. Do not paste them in chat or on GitHub.
import { generateKeyPairSync, randomBytes } from "node:crypto";

const b64u = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

const lines = {
  ADMIN_API_KEY: b64u(randomBytes(32)),
  JWT_SECRET: b64u(randomBytes(32)),
  DATA_KEY: randomBytes(32).toString("base64"),
  LICENSE_PRIVATE_KEY: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
  LICENSE_PUBLIC_KEY: b64u(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url")),
};

console.log("\nCopy these into your private notes. Each one is a SECRET.\n");
for (const [k, v] of Object.entries(lines)) console.log(`${k}=${v}`);
console.log("\nWARNING: if you lose LICENSE_PRIVATE_KEY or DATA_KEY you cannot recover them, and if you");
console.log("generate new ones later, every issued licence / authenticator setup stops working.\n");
