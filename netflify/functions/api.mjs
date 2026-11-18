import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";

export const config = { path: "/api/*" };

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const hashPw = (pw, salt) => scryptSync(pw, salt, 32);
const newAuth = (pw) => { const salt = randomBytes(16); return { salt: salt.toString("hex"), hash: hashPw(pw, salt).toString("hex") }; };
const same = (rec, pw) => {
  const h = hashPw(pw, Buffer.from(rec.salt, "hex")), e = Buffer.from(rec.hash, "hex");
  return h.length === e.length && timingSafeEqual(h, e);
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

export default async (req) => {
  const st = getStore("primewave");
  const route = new URL(req.url).pathname.replace(/^\/api\/?/, "");
  const env = process.env.ADMIN_PASSWORD || "";
  let auth = await st.get("auth", { type: "json" });
  const needSetup = !auth && !env;

  if (route === "public" && req.method === "GET") {
    const pub = (await st.get("public", { type: "json" })) || {};
    return J({ pub: pub.pub, settings: pub.settings, setup: needSetup });
  }
  if (req.method !== "POST") return J({ error: "not found" }, 404);

  let b = {};
  try { b = await req.json(); } catch (e) { return J({ error: "bad request" }, 400); }

  if (route === "setup") {
    if (!needSetup) return J({ error: "already set up" }, 403);
    if (typeof b.password !== "string" || b.password.length < 8) return J({ error: "short" }, 400);
    await st.setJSON("auth", newAuth(b.password));
    await st.setJSON("private", { orders: Array.isArray(b.orders) ? b.orders : [], settings: b.settings || null });
    await st.setJSON("meta", { savedAt: Date.now(), publishedAt: 0 });
    return J({ ok: true });
  }

  const pw = typeof b.password === "string" ? b.password : "";
  let ok = false;
  if (auth) ok = same(auth, pw);
  else if (env && pw.length === env.length && timingSafeEqual(Buffer.from(pw), Buffer.from(env))) { auth = newAuth(pw); await st.setJSON("auth", auth); ok = true; }
  if (!ok) { await wait(600); return J({ error: "unauthorized" }, 401); }

  const meta = (await st.get("meta", { type: "json" })) || { savedAt: 0, publishedAt: 0 };

  if (route === "login") {
    const p = await st.get("private", { type: "json" });
    return J({ ok: true, orders: p ? p.orders : null, settings: p ? p.settings : null, dirty: meta.savedAt > meta.publishedAt });
  }
  if (route === "save") {
    if (!Array.isArray(b.orders)) return J({ error: "bad request" }, 400);
    await st.setJSON("private", { orders: b.orders, settings: b.settings || null });
    await st.setJSON("meta", { ...meta, savedAt: Date.now() });
    return J({ ok: true });
  }
  if (route === "publish") {
    if (!Array.isArray(b.pub)) return J({ error: "bad request" }, 400);
    await st.setJSON("public", { pub: b.pub, settings: b.settings || null });
    await st.setJSON("meta", { ...meta, publishedAt: Date.now() + 1 });
    return J({ ok: true });
  }
  if (route === "password") {
    if (typeof b.next !== "string" || b.next.length < 8) return J({ error: "short" }, 400);
    await st.setJSON("auth", newAuth(b.next));
    return J({ ok: true });
  }
  return J({ error: "not found" }, 404);
};
