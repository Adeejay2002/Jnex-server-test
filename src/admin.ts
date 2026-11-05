// Vendor (Jnex staff) operations: create shops + owner logins, approve POS machines,
// extend licences, reset a locked-out owner. Protected by ADMIN_API_KEY.
// (A proper admin login with its own MFA replaces this key later.)
import type { Ctx, Owner } from "./types";
import { HttpError, json, readJson, str, email as emailField } from "./http";
import { randomBytes, safeEqualStrings } from "./crypto";
import { deviceCodeFor } from "./devices";

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I: easy to read out over the phone
const PASS_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

function randomFrom(alphabet: string, n: number): string {
  const bytes = randomBytes(n);
  let s = "";
  for (let i = 0; i < n; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
}
export const newShopCode = (): string => `JX-${randomFrom(CODE_ALPHABET, 8)}`;
export function temporaryPassword(): string {
  for (;;) {
    const p = randomFrom(PASS_ALPHABET, 14);
    if (/[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p)) return p;
  }
}

export async function requireAdmin(ctx: Ctx): Promise<void> {
  const key = ctx.env.ADMIN_API_KEY;
  if (!key || key.length < 32) throw new HttpError(503, "not_configured", "Admin key is not configured on the server.");
  const failKey = `admin-fail:${ctx.ip}`;
  if ((await ctx.repo.rateCount(failKey, 600)) >= 10) throw new HttpError(429, "too_many_attempts", "Too many wrong keys. Try again in 10 minutes.", { retryAfter: 600 });
  const h = ctx.req.headers.get("authorization") || "";
  const given = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!given || !(await safeEqualStrings(given, key))) {
    await ctx.repo.rateHit(failKey, 600);
    throw new HttpError(401, "unauthorized", "Wrong admin key.");
  }
}

const ownerView = (o: Owner) => ({ id: o.id, email: o.email, name: o.name, mfaEnabled: o.mfaEnabled, mustChangePassword: o.mustChangePassword, status: o.status, lastLoginAt: o.lastLoginAt });

export async function createTenant(ctx: Ctx): Promise<Response> {
  await requireAdmin(ctx);
  const body = await readJson(ctx.req);
  const name = str(body.name, "shop name", 2, 80);
  const plan = typeof body.plan === "string" && body.plan ? str(body.plan, "plan", 1, 30) : "standard";
  const days = body.licenseDays === undefined ? 30 : Number(body.licenseDays);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new HttpError(400, "invalid_input", "licenseDays must be 1-3650.");
  const licenseExpiresAt = new Date(ctx.now().getTime() + days * 86400000).toISOString();

  let tenant = null;
  for (let i = 0; i < 5 && !tenant; i++) {
    try {
      tenant = await ctx.repo.createTenant({ code: newShopCode(), name, plan, licenseExpiresAt });
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 409)) throw e; // code clash: try another
    }
  }
  if (!tenant) throw new HttpError(500, "code_clash", "Could not create a unique shop code. Try again.");
  await ctx.repo.audit({ tenantId: tenant.id, actor: "admin", action: "tenant.created", details: { name, plan, days } });
  return json({ tenant }, 201);
}

export async function createOwner(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  const tenant = await ctx.repo.getTenant(params.id);
  if (!tenant) throw new HttpError(404, "not_found", "Shop not found.");
  const body = await readJson(ctx.req);
  const email = emailField(body.email);
  const name = str(body.name, "name", 2, 80);
  const password = temporaryPassword();
  const owner = await ctx.repo.createOwner({ tenantId: tenant.id, email, name, password, mustChangePassword: true });
  await ctx.repo.audit({ tenantId: tenant.id, actor: "admin", action: "owner.created", details: { email } });
  // shown once: the vendor passes it to the customer, who must change it at first login
  return json({ owner: ownerView(owner), temporaryPassword: password }, 201);
}

export async function listTenants(ctx: Ctx): Promise<Response> {
  await requireAdmin(ctx);
  return json({ tenants: await ctx.repo.listTenants() });
}

export async function listOwners(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  return json({ owners: (await ctx.repo.listOwners(params.id)).map(ownerView) });
}

export async function extendLicense(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  const tenant = await ctx.repo.getTenant(params.id);
  if (!tenant) throw new HttpError(404, "not_found", "Shop not found.");
  const body = await readJson(ctx.req);
  const days = Number(body.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new HttpError(400, "invalid_input", "days must be 1-3650.");
  const nowMs = ctx.now().getTime();
  const base = Math.max(nowMs, tenant.licenseExpiresAt ? Date.parse(tenant.licenseExpiresAt) : nowMs); // renewing early never loses days
  const expiresAt = new Date(base + days * 86400000).toISOString();
  await ctx.repo.setTenantLicense(tenant.id, expiresAt);
  await ctx.repo.audit({ tenantId: tenant.id, actor: "admin", action: "license.extended", details: { days, expiresAt } });
  return json({ licenseExpiresAt: expiresAt });
}

export async function listDevices(ctx: Ctx): Promise<Response> {
  await requireAdmin(ctx);
  const status = ctx.url.searchParams.get("status");
  const tenantId = ctx.url.searchParams.get("tenantId") || undefined;
  if (status && !["pending", "active", "revoked"].includes(status)) throw new HttpError(400, "invalid_input", "Unknown status.");
  return json({ devices: await ctx.repo.listDevices({ status: (status as any) || undefined, tenantId }) });
}

export async function approveDevice(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  const device = await ctx.repo.getDevice(params.id);
  if (!device) throw new HttpError(404, "not_found", "Machine not found.");
  if (device.status === "active") return json({ device });
  // keeps the same letter if the machine was approved before; new machines get the next letter
  let code = device.deviceCode;
  let result = null;
  for (let attempt = 0; attempt < 3 && !result; attempt++) {
    code = device.deviceCode ?? deviceCodeFor((await ctx.repo.countDeviceCodes(device.tenantId)) + attempt);
    try {
      result = await ctx.repo.approveDevice(device.id, code);
    } catch (e) {
      if (!(e instanceof HttpError && e.status === 409)) throw e;
    }
  }
  if (!result) throw new HttpError(500, "code_clash", "Could not assign a machine letter. Try again.");
  await ctx.repo.audit({ tenantId: device.tenantId, actor: "admin", action: "device.approved", details: { deviceId: device.id, code } });
  return json({ device: result });
}

export async function revokeDevice(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  const body = await readJson(ctx.req).catch(() => ({} as Record<string, unknown>));
  const reason = typeof body.reason === "string" && body.reason ? body.reason.slice(0, 200) : "deactivated by admin";
  const device = await ctx.repo.revokeDevice(params.id, reason);
  if (!device) throw new HttpError(404, "not_found", "Machine not found.");
  await ctx.repo.audit({ tenantId: device.tenantId, actor: "admin", action: "device.revoked", details: { deviceId: device.id, reason } });
  return json({ device });
}

// Owner lost their phone / forgot the password
export async function resetOwner(ctx: Ctx, params: Record<string, string>): Promise<Response> {
  await requireAdmin(ctx);
  const owner = await ctx.repo.getOwner(params.id);
  if (!owner) throw new HttpError(404, "not_found", "Owner not found.");
  const body = await readJson(ctx.req).catch(() => ({} as Record<string, unknown>));
  const out: Record<string, unknown> = {};
  if (body.mfa === true) {
    await ctx.repo.setOwnerMfa(owner.id, { secretEnc: null, enabled: false });
    out.mfaReset = true;
  }
  if (body.password === true) {
    const p = temporaryPassword();
    await ctx.repo.setOwnerPassword(owner.id, p, true);
    out.temporaryPassword = p;
  }
  if (!out.mfaReset && !out.temporaryPassword) throw new HttpError(400, "invalid_input", "Send { mfa: true } and/or { password: true }.");
  await ctx.repo.revokeAllSessions(owner.id);
  await ctx.repo.audit({ tenantId: owner.tenantId, actor: "admin", action: "owner.reset", details: { mfa: !!out.mfaReset, password: !!out.temporaryPassword } });
  return json(out);
}

// ---- the admin page (served at /admin) ---------------------------------------
export function adminPage(nonce: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jnex admin</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#f4f5f7;color:#1c1f26}main{max-width:980px;margin:0 auto;padding:16px}
h1{font-size:18px}h2{font-size:15px;margin:22px 0 8px}section{background:#fff;border:1px solid #dde0e6;border-radius:8px;padding:12px 14px;margin-bottom:12px}
input,select,button{font:inherit;padding:7px 9px;border:1px solid #c5c9d1;border-radius:6px}button{background:#1f6feb;color:#fff;border:0;cursor:pointer}button.sec{background:#e8eaef;color:#1c1f26}button.red{background:#c62828}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 4px;border-bottom:1px solid #eceef2;vertical-align:top}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}
.muted{color:#6b7280;font-size:12px}.ok{color:#1b7f3b}.bad{color:#c62828}code{background:#eef0f4;padding:1px 5px;border-radius:4px}#msg{white-space:pre-wrap;padding:8px;border-radius:6px;background:#fff8e1;display:none;margin-bottom:10px}
</style></head><body><main>
<h1>Jnex admin</h1>
<section><div class="row"><div><label class="muted">Admin key</label><br><input id="key" type="password" size="40" autocomplete="off"></div><button id="go">Connect</button><span class="muted">The key stays in this page only (not saved).</span></div></section>
<div id="msg"></div>
<div id="app" style="display:none">
<h2>Machines waiting for approval</h2><section><table id="pending"></table></section>
<h2>New shop</h2><section><div class="row"><div><label class="muted">Shop name</label><br><input id="shopName" size="28"></div>
<div><label class="muted">Licence days</label><br><input id="days" type="number" value="30" style="width:90px"></div><button id="mkShop">Create shop</button></div></section>
<h2>Shops</h2><section><table id="tenants"></table></section>
</div>
<script nonce="${nonce}">
const $=id=>document.getElementById(id);let KEY="";
function msg(t,bad){const m=$("msg");m.style.display=t?"block":"none";m.textContent=t||"";m.style.background=bad?"#fdecea":"#fff8e1"}
async function api(path,method="GET",body){const r=await fetch(path,{method,headers:{"authorization":"Bearer "+KEY,"content-type":"application/json"},body:body?JSON.stringify(body):undefined});
const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error((j.error&&j.error.message)||("Error "+r.status));return j}
function cell(tr,t,cls){const td=document.createElement("td");td.textContent=t==null?"":t;if(cls)td.className=cls;tr.appendChild(td);return td}
function btn(td,label,cls,fn){const b=document.createElement("button");b.textContent=label;b.className=cls||"";b.style.marginRight="4px";b.onclick=async()=>{try{await fn();await load()}catch(e){msg(e.message,true)}};td.appendChild(b)}
function head(t,cols){t.textContent="";const tr=document.createElement("tr");cols.forEach(c=>{const th=document.createElement("th");th.textContent=c;tr.appendChild(th)});t.appendChild(tr)}
async function load(){msg("");const [p,t]=await Promise.all([api("/v1/admin/devices?status=pending"),api("/v1/admin/tenants")]);
head($("pending"),["Shop","Machine","Registered","Version",""]);
if(!p.devices.length){const tr=document.createElement("tr");cell(tr,"Nothing waiting.","muted");$("pending").appendChild(tr)}
p.devices.forEach(d=>{const tr=document.createElement("tr");cell(tr,d.tenantName);cell(tr,d.name+" ("+d.hwHash.slice(0,8)+")");cell(tr,new Date(d.createdAt).toLocaleString());cell(tr,d.appVersion||"");
const td=cell(tr,"");btn(td,"Approve","",()=>api("/v1/admin/devices/"+d.id+"/approve","POST",{}));btn(td,"Reject","red",()=>api("/v1/admin/devices/"+d.id+"/revoke","POST",{reason:"rejected"}));$("pending").appendChild(tr)});
head($("tenants"),["Shop","Shop code","Licence until","Machines","Owners",""]);
t.tenants.forEach(x=>{const tr=document.createElement("tr");cell(tr,x.name+(x.status!=="active"?" (suspended)":""));const c=cell(tr,"");const code=document.createElement("code");code.textContent=x.code;c.appendChild(code);
cell(tr,x.licenseExpiresAt?new Date(x.licenseExpiresAt).toLocaleDateString():"no expiry",x.licenseExpiresAt&&Date.parse(x.licenseExpiresAt)<Date.now()?"bad":"");
cell(tr,x.activeDevices+" active, "+x.pendingDevices+" waiting");cell(tr,x.ownerCount);const td=cell(tr,"");
btn(td,"+ Owner","sec",async()=>{const email=prompt("Owner email");if(!email)return;const name=prompt("Owner name");if(!name)return;const r=await api("/v1/admin/tenants/"+x.id+"/owners","POST",{email,name});prompt("Temporary password (copy it now, it is shown once):",r.temporaryPassword)});
btn(td,"+ 30 days","sec",()=>api("/v1/admin/tenants/"+x.id+"/license","POST",{days:30}));
btn(td,"+ 1 year","sec",()=>api("/v1/admin/tenants/"+x.id+"/license","POST",{days:365}));
btn(td,"Owners","sec",async()=>{const r=await api("/v1/admin/tenants/"+x.id+"/owners");
const o=r.owners.map(o=>o.email+" | authenticator "+(o.mfaEnabled?"on":"off")+" | id "+o.id).join("\\n")||"none";
const id=prompt(o+"\\n\\nTo reset someone, type: id,mfa or id,password (or id,mfa,password)","");if(!id)return;const [oid,...w]=id.split(",").map(s=>s.trim());
const res=await api("/v1/admin/owners/"+oid+"/reset","POST",{mfa:w.includes("mfa"),password:w.includes("password")});if(res.temporaryPassword)prompt("New temporary password (shown once):",res.temporaryPassword);else msg("Done.")});
$("tenants").appendChild(tr)})}
$("go").onclick=async()=>{KEY=$("key").value.trim();try{await load();$("app").style.display="block"}catch(e){msg(e.message,true)}};
$("mkShop").onclick=async()=>{try{const r=await api("/v1/admin/tenants","POST",{name:$("shopName").value,licenseDays:Number($("days").value)});msg("Shop created. Shop code: "+r.tenant.code+"\\nNow click '+ Owner' on that row.");$("shopName").value="";await load()}catch(e){msg(e.message,true)}};
</script></main></body></html>`;
}
