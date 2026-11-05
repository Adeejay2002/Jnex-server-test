import type { Ctx } from "./types";

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public extra?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
}

export function errorResponse(e: HttpError): Response {
  const headers: Record<string, string> = {};
  if (e.status === 429 && typeof e.extra?.retryAfter === "number") headers["retry-after"] = String(e.extra.retryAfter);
  return json({ error: { code: e.code, message: e.message, ...(e.extra || {}) } }, e.status, headers);
}

// Only JSON bodies, only small ones.
export async function readJson(req: Request, maxBytes = 64 * 1024): Promise<Record<string, unknown>> {
  const ct = req.headers.get("content-type") || "";
  if (!ct.toLowerCase().startsWith("application/json")) throw new HttpError(415, "unsupported_media_type", "Send JSON (Content-Type: application/json).");
  const text = await req.text();
  if (text.length > maxBytes) throw new HttpError(413, "payload_too_large", "Request is too large.");
  try {
    const v = JSON.parse(text);
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
    return v as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "bad_json", "Request body is not valid JSON.");
  }
}

export function str(v: unknown, name: string, min: number, max: number): string {
  if (typeof v !== "string") throw new HttpError(400, "invalid_input", `${name} is required.`);
  const s = v.trim();
  if (s.length < min || s.length > max) throw new HttpError(400, "invalid_input", `${name} must be ${min}-${max} characters.`);
  return s;
}
export function email(v: unknown): string {
  const s = str(v, "email", 5, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) throw new HttpError(400, "invalid_input", "That email address is not valid.");
  return s;
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export const SESSION_COOKIE = "jnex_session";

export function sessionCookie(ctx: Ctx, token: string, maxAgeSec: number): string {
  const secure = ctx.env.ENVIRONMENT === "dev" ? "" : "; Secure";
  return `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
export function clearSessionCookie(ctx: Ctx): string {
  return sessionCookie(ctx, "", 0);
}
