// Supabase Edge Function: inquiry
// The Pardis token never leaves the server. The page sends only the inquiry
// payload with the user's own login; this function reads the token, calls
// Pardis, retries if the token was just rotated, and returns Pardis's answer.
import { createClient } from "jsr:@supabase/supabase-js@2";

const PARDIS_URL = "https://apigateway.pardisinsure.com/CoreInsurance/Sanhab/Policy/Inquiry/smart-inquiry";
const TOKEN_KEY = "sanhab_token";
const SB_URL = Deno.env.get("SUPABASE_URL");
const ANON = Deno.env.get("SUPABASE_ANON_KEY");
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const MAX_BODY = 20000;          // bytes of payload
const RATE_PER_MIN = 60;         // inquiries per user per minute
const WAIT_ROUNDS = 8;           // after a rejection: re-read token once per second, this many times

const sb = createClient(SB_URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, accept, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Expose-Headers": "x-sanhab-err, x-sanhab-up",
};

function reply(status, obj, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, "Content-Type": "application/json", ...(extra || {}) },
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function cleanToken(t) {
  t = String(t || "").trim().replace(/^["']+|["']+$/g, "");
  if (t.toLowerCase().indexOf("bearer ") === 0) t = t.slice(7).trim();
  return t;
}
function parseToken(j) {
  if (j === null || j === undefined) return "";
  if (typeof j === "string") return cleanToken(j);
  if (typeof j.value === "string" && j.value) return cleanToken(j.value);
  if (j.data && typeof j.data.value === "string" && j.data.value) return cleanToken(j.data.value);
  if (typeof j.token === "string" && j.token) return cleanToken(j.token);
  if (typeof j.access_token === "string" && j.access_token) return cleanToken(j.access_token);
  if (j.data && typeof j.data.token === "string") return cleanToken(j.data.token);
  if (j.result && typeof j.result === "string") return cleanToken(j.result);
  return "";
}

let cache = { t: "", at: 0 };
async function readToken() {
  try {
    const r = await fetch(`${SB_URL}/functions/v1/get-value/${encodeURIComponent(TOKEN_KEY)}`, {
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return "";
    const txt = await r.text();
    let j;
    try { j = JSON.parse(txt); } catch { j = txt; }
    return parseToken(j);
  } catch { return ""; }
}
async function getToken(force) {
  if (!force && cache.t && Date.now() - cache.at < 2000) return cache.t;
  const t = await readToken();
  if (t) cache = { t, at: Date.now() };
  return t || cache.t;
}

async function callPardis(token, body) {
  return await fetch(PARDIS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", Authorization: `Bearer ${token}` },
    body,
    signal: AbortSignal.timeout(15000),
  });
}
async function pass(r) {
  return new Response(await r.text(), {
    status: r.status,
    headers: { ...CORS, "Content-Type": r.headers.get("content-type") || "application/json" },
  });
}

const hits = new Map();
function limited(uid) {
  const now = Date.now();
  const h = hits.get(uid);
  if (!h || now > h.reset) { hits.set(uid, { n: 1, reset: now + 60000 }); return false; }
  h.n++;
  return h.n > RATE_PER_MIN;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return reply(405, { error: "method" });

  // 1) who is asking? must be a logged-in user
  const jwt = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  let user = null;
  try { const { data, error } = await sb.auth.getUser(jwt); if (!error) user = data && data.user; } catch { /* ignore */ }
  if (!user) return reply(401, { error: "auth" }, { "x-sanhab-err": "auth" });
  if (limited(user.id)) return reply(429, { error: "rate" });

  // 2) payload sanity
  const body = await req.text();
  if (!body || body.length > MAX_BODY) return reply(413, { error: "size" });
  try { const o = JSON.parse(body); if (!o || typeof o !== "object" || Array.isArray(o)) throw 0; }
  catch { return reply(400, { error: "payload" }); }

  // 3) call Pardis; if the token was just rotated, pick up the new one and retry
  let token = await getToken(false);
  let tried = "";
  let last = 401;
  try {
    for (let i = 0; i <= WAIT_ROUNDS; i++) {
      if (token && token !== tried) {
        tried = token;
        const r = await callPardis(token, body);
        if (r.status !== 401 && r.status !== 403) {
          console.log(JSON.stringify({ u: user.email, s: r.status, round: i }));
          return await pass(r);
        }
        last = r.status;
      }
      if (i === WAIT_ROUNDS) break;
      const fresh = await getToken(true);
      if (fresh && fresh !== token) { token = fresh; continue; }  // new token: try again right away
      await sleep(1000);
    }
  } catch (e) {
    console.log(JSON.stringify({ u: user.email, err: String(e) }));
    return reply(502, { error: "net" }, { "x-sanhab-err": "net" });
  }
  console.log(JSON.stringify({ u: user.email, s: last, upstream: true }));
  return reply(503, { error: "upstream" }, { "x-sanhab-err": "upstream", "x-sanhab-up": String(last) });
});
