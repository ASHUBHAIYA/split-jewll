// ATITS relay + license Worker
//
//  D1 (env.DATABASE)       : admin PIN + licenses only. Read on push / connect (cached 60 s), never written while idle.
//  RelayRoom (env.RELAY_ROOM): one Durable Object per license. Holds the job queue, delivers jobs to the bridge over a
//                             hibernating WebSocket (new bridge) or a 20 s long-poll (old bridge), and tracks "online"
//                             in memory, so heartbeats cost no database writes at all.
import { DurableObject } from "cloudflare:workers";

const PENDING_TTL_MS = 45_000; // a job nobody picked up is dropped (the browser has long since reported "bridge offline")
const INPROGRESS_TTL_MS = 5 * 60_000; // bridge took the job but never reported a result
const RESULT_KEEP_MS = 10 * 60_000; // finished jobs (and their big Tally responses) are deleted after this
const POLL_HOLD_MS = 20_000; // legacy long-poll hold
const MAX_WAIT_S = 25; // max ?wait= for /relay/status
const ONLINE_WINDOW_MS = 60_000; // legacy poller counts as online if seen within this window
const MAX_ROW_BYTES = 1_800_000; // Durable Object / D1 rows are limited to 2 MB
const GUARD_MAX_FAILS = 5;
const GUARD_WINDOW_MS = 10 * 60_000;

const enc = new TextEncoder();

// ---------------------------------------------------------------- helpers
function corsFor(request, env) {
  const allowed = String(env.ALLOWED_ORIGIN || "*").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = request.headers.get("Origin") || "";
  let allow = "*";
  if (!allowed.includes("*")) allow = allowed.includes(origin) ? origin : allowed[0] || "";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-License-Key, X-Admin-PIN",
    "Vary": "Origin",
  };
}

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(s) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));
}

// Durable Object name for a license. Hashing keeps the license key out of object names/logs.
async function routeIdFor(licenseKey) {
  return (await sha256Hex("relay:" + licenseKey)).slice(0, 24);
}

function roomFor(env, routeId) {
  return env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(routeId));
}

const JOB_ID_RE = /^([0-9a-f]{24})\.([0-9a-f-]{36})$/;

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------------------------------------------------------------- licenses (D1, cached per isolate)
const licCache = new Map();

async function getLicense(env, key) {
  key = String(key || "").trim();
  if (!key || key.length > 64) return null;
  const hit = licCache.get(key);
  if (hit && hit.exp > Date.now()) return hit.rec;
  const rec = await env.DATABASE
    .prepare("SELECT status, expires_at, store_name, machine_id FROM licenses WHERE license_key = ?")
    .bind(key)
    .first();
  if (licCache.size > 500) licCache.clear();
  licCache.set(key, { rec: rec || null, exp: Date.now() + (rec ? 60_000 : 30_000) });
  return rec || null;
}

function licenseOk(rec) {
  if (!rec || rec.status !== "active") return false;
  const today = new Date().toISOString().split("T")[0];
  return !(rec.expires_at && rec.expires_at < today);
}

// ---------------------------------------------------------------- admin PIN
async function hashPin(pin, saltHex) {
  return `sha256$${saltHex}$${await sha256Hex(`${saltHex}:${pin}`)}`;
}

async function newPinHash(pin) {
  return hashPin(pin, hex(crypto.getRandomValues(new Uint8Array(16))));
}

async function checkPin(stored, pin) {
  if (!stored) return false;
  if (stored.startsWith("sha256$")) {
    const salt = stored.split("$")[1] || "";
    return timingSafeEqual(await hashPin(pin, salt), stored);
  }
  return timingSafeEqual(stored.trim(), pin); // legacy plain-text PIN, upgraded to a hash on first successful login
}

function guardStub(env) {
  return roomFor(env, "__admin__");
}

async function guardBlocked(env, ip) {
  const r = await guardStub(env).fetch("https://relay/guard/check?ip=" + encodeURIComponent(ip));
  return r.status === 429;
}

async function guardFail(env, ip) {
  await guardStub(env).fetch("https://relay/guard/fail?ip=" + encodeURIComponent(ip));
}

// Returns null when the request carries a valid admin PIN, otherwise a Response to send back.
async function requireAdmin(request, env, cors) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (await guardBlocked(env, ip)) return json({ error: "Too many wrong PIN attempts. Try again in 10 minutes." }, 429, cors);
  const pin = (request.headers.get("X-Admin-PIN") || "").trim();
  let ok = false;
  if (pin) {
    if (env.ADMIN_PIN) ok = timingSafeEqual(String(env.ADMIN_PIN), pin);
    else {
      const row = await env.DATABASE.prepare("SELECT value FROM admin_config WHERE key = 'ADMIN_MASTER_PIN'").first();
      ok = !!row && (await checkPin(row.value, pin));
    }
  }
  if (!ok) {
    await guardFail(env, ip);
    return json({ error: "Admin PIN required" }, 401, cors);
  }
  return null;
}

// ---------------------------------------------------------------- Worker entry
export default {
  async fetch(request, env) {
    const cors = corsFor(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    if (!env.DATABASE) {
      return json({ error: "D1 binding 'DATABASE' not found. Bind your D1 database with variable name DATABASE." }, 500, cors);
    }
    if (!env.RELAY_ROOM) {
      return json({ error: "Durable Object binding 'RELAY_ROOM' not found. Deploy with the provided wrangler.toml." }, 500, cors);
    }

    try {
      return await route(request, env, cors);
    } catch (err) {
      return json({ error: "Internal error", detail: String((err && err.message) || err) }, 500, cors);
    }
  },
};

async function route(request, env, cors) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  // ---- admin PIN -----------------------------------------------------------------------------
  if (path === "/verify" && method === "POST") {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (await guardBlocked(env, ip)) return json({ valid: false, error: "Too many wrong PIN attempts. Try again in 10 minutes." }, 429, cors);

    const { pin } = await request.json().catch(() => ({}));
    const entered = String(pin || "").trim();

    if (env.ADMIN_PIN) {
      const valid = entered !== "" && timingSafeEqual(String(env.ADMIN_PIN), entered);
      if (!valid) await guardFail(env, ip);
      return json({ valid }, 200, cors);
    }

    const row = await env.DATABASE.prepare("SELECT value FROM admin_config WHERE key = 'ADMIN_MASTER_PIN'").first();
    if (!row || !row.value) {
      if (entered.length >= 4) {
        await env.DATABASE
          .prepare("INSERT INTO admin_config (key, value) VALUES ('ADMIN_MASTER_PIN', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
          .bind(await newPinHash(entered))
          .run();
        return json({ valid: true, initialized: true }, 200, cors);
      }
      return json({ valid: false, error: "No PIN initialized" }, 200, cors);
    }

    const valid = entered !== "" && (await checkPin(row.value, entered));
    if (!valid) {
      await guardFail(env, ip);
    } else if (!row.value.startsWith("sha256$")) {
      // one-time upgrade of a legacy plain-text PIN
      await env.DATABASE
        .prepare("UPDATE admin_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'ADMIN_MASTER_PIN'")
        .bind(await newPinHash(entered))
        .run();
    }
    return json({ valid }, 200, cors);
  }

  if ((path === "/set" && (method === "POST" || method === "PUT")) || (path === "/" && method === "PUT")) {
    if (env.ADMIN_PIN) return json({ success: false, error: "PIN is managed by the ADMIN_PIN secret." }, 400, cors);
    const { pin, value } = await request.json().catch(() => ({}));
    const newPin = String(pin || value || "").trim();
    if (newPin.length < 4) return json({ success: false, error: "PIN must be at least 4 digits" }, 400, cors);

    const existing = await env.DATABASE.prepare("SELECT value FROM admin_config WHERE key = 'ADMIN_MASTER_PIN'").first();
    if (existing && existing.value) {
      const denied = await requireAdmin(request, env, cors); // changing an existing PIN needs the current one
      if (denied) return denied;
    }
    await env.DATABASE
      .prepare("INSERT INTO admin_config (key, value) VALUES ('ADMIN_MASTER_PIN', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP")
      .bind(await newPinHash(newPin))
      .run();
    return json({ success: true, key: "ADMIN_MASTER_PIN" }, 200, cors);
  }

  // ---- license creation (admin only) ------------------------------------------------------------
  if (path === "/create-key" && method === "POST") {
    const denied = await requireAdmin(request, env, cors);
    if (denied) return denied;

    const body = await request.json().catch(() => ({}));
    const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 symbols -> no modulo bias with a random byte
    const chunk = () => Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) => chars[b % 32]).join("");
    const licenseKey = `JWEL-${chunk()}-${chunk()}-${chunk()}`;

    const durationMonths = Math.min(Math.max(parseInt(body.durationMonths || 12, 10) || 12, 1), 120);
    const expiry = new Date();
    expiry.setMonth(expiry.getMonth() + durationMonths);
    const storeName = String(body.storeName || "Jewellery Store").slice(0, 120);
    const contactInfo = String(body.contactInfo || "").slice(0, 200);
    const createdAt = new Date().toISOString().split("T")[0];
    const expiresAt = expiry.toISOString().split("T")[0];

    await env.DATABASE
      .prepare("INSERT INTO licenses (license_key, store_name, contact_info, duration_months, created_at, expires_at, machine_id, status) VALUES (?, ?, ?, ?, ?, ?, '', 'active')")
      .bind(licenseKey, storeName, contactInfo, durationMonths, createdAt, expiresAt)
      .run();

    return json({ success: true, licenseKey, record: { licenseKey, storeName, contactInfo, durationMonths, createdAt, expiresAt, status: "active" } }, 200, cors);
  }

  // ---- bridge start-up license check (runs once per bridge start) ---------------------------------
  if (path === "/verify-license" && method === "POST") {
    const { licenseKey, machineId } = await request.json().catch(() => ({}));
    if (!licenseKey) return json({ success: false, error: "License key is required" }, 400, cors);

    const cleanKey = String(licenseKey).trim();
    const record = await env.DATABASE.prepare("SELECT * FROM licenses WHERE license_key = ?").bind(cleanKey).first();
    if (!record) return json({ success: false, error: `Invalid license key: ${cleanKey}` }, 404, cors);
    if (record.status !== "active") return json({ success: false, error: "License is disabled or revoked" }, 403, cors);
    const today = new Date().toISOString().split("T")[0];
    if (record.expires_at && record.expires_at < today) {
      return json({ success: false, error: `License expired on ${record.expires_at}` }, 403, cors);
    }

    if (!record.machine_id && machineId) {
      await env.DATABASE.prepare("UPDATE licenses SET machine_id = ?, updated_at = CURRENT_TIMESTAMP WHERE license_key = ?").bind(machineId, cleanKey).run();
      licCache.delete(cleanKey);
    } else if (record.machine_id && machineId && record.machine_id !== machineId) {
      return json({ success: false, error: "License is already registered to a different computer" }, 403, cors);
    }

    return json({ success: true, status: record.status, expires_at: record.expires_at, storeName: record.store_name, machineId: record.machine_id || machineId }, 200, cors);
  }

  // ---- relay: browser pushes a job --------------------------------------------------------------
  if (path === "/relay/push" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const licenseKey = String(body.licenseKey || "").trim();
    if (!licenseKey || licenseKey === "DEFAULT") return json({ error: "licenseKey is required" }, 400, cors);
    if (!licenseOk(await getLicense(env, licenseKey))) return json({ error: "Invalid or expired license" }, 403, cors);

    const xml = typeof body.xml === "string" ? body.xml : "";
    if (!xml) return json({ error: "xml is required" }, 400, cors);
    if (enc.encode(xml).length > MAX_ROW_BYTES) return json({ error: "Payload too large (max ~1.8 MB). Split the push into smaller batches." }, 413, cors);

    const routeId = await routeIdFor(licenseKey);
    const r = await roomFor(env, routeId).fetch("https://relay/push", { method: "POST", body: JSON.stringify({ xml, routeId }) });
    return json(await r.json(), r.status, cors);
  }

  // ---- relay: old bridge long-poll ----------------------------------------------------------------
  if (path === "/relay/poll" && method === "GET") {
    const licenseKey = (request.headers.get("X-License-Key") || url.searchParams.get("licenseKey") || "").trim();
    if (!licenseKey) return json({ pending: false, error: "licenseKey required" }, 400, cors);
    if (!licenseOk(await getLicense(env, licenseKey))) return json({ pending: false, error: "Invalid or expired license" }, 403, cors);
    const r = await roomFor(env, await routeIdFor(licenseKey)).fetch("https://relay/poll");
    return json(await r.json(), r.status, cors);
  }

  // ---- relay: new bridge WebSocket ------------------------------------------------------------------
  if (path === "/relay/ws" && method === "GET") {
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") return json({ error: "Expected a WebSocket upgrade" }, 426, cors);
    const licenseKey = (request.headers.get("X-License-Key") || url.searchParams.get("licenseKey") || "").trim();
    if (!licenseKey) return json({ error: "licenseKey required" }, 400, cors);
    if (!licenseOk(await getLicense(env, licenseKey))) return json({ error: "Invalid or expired license" }, 403, cors);
    return roomFor(env, await routeIdFor(licenseKey)).fetch(new Request("https://relay/ws", request));
  }

  // ---- relay: bridge reports a result (works for old and new bridges) -----------------------------
  if (path === "/relay/status" && method === "POST") {
    const { jobId, status, error, tallyResponse } = await request.json().catch(() => ({}));
    const m = JOB_ID_RE.exec(String(jobId || ""));
    if (!m) return json({ error: "valid jobId is required" }, 400, cors);
    const r = await roomFor(env, m[1]).fetch("https://relay/result", {
      method: "POST",
      body: JSON.stringify({ jobId, status, error, tallyResponse }),
    });
    return json(await r.json(), r.status, cors);
  }

  // ---- relay: browser waits for a job result (long-poll) -----------------------------------------
  if (path === "/relay/status" && method === "GET" && url.searchParams.get("jobId")) {
    const jobId = url.searchParams.get("jobId");
    const m = JOB_ID_RE.exec(jobId);
    if (!m) return json({ error: "valid jobId required" }, 400, cors);
    const wait = Math.min(Math.max(Number(url.searchParams.get("wait")) || 0, 0), MAX_WAIT_S);
    const r = await roomFor(env, m[1]).fetch(`https://relay/status?jobId=${encodeURIComponent(jobId)}&wait=${wait}`);
    return json(await r.json(), r.status, cors);
  }

  // ---- relay: is the bridge online? ----------------------------------------------------------------
  if ((path === "/relay/daemon-status" || path === "/relay/status") && method === "GET") {
    const licenseKey = (url.searchParams.get("licenseKey") || request.headers.get("X-License-Key") || "").trim();
    if (!licenseKey || !licenseOk(await getLicense(env, licenseKey))) {
      return json({ online: false, lastSeenSecondsAgo: null }, 200, cors);
    }
    const r = await roomFor(env, await routeIdFor(licenseKey)).fetch("https://relay/daemon");
    return json(await r.json(), r.status, cors);
  }

  if (path === "/" && method === "GET") {
    return json({ status: "ATITS relay active", transport: "websocket + long-poll", database: "D1 (licenses) + Durable Objects (relay)" }, 200, cors);
  }

  return json({ error: "Not found" }, 404, cors);
}

// ---------------------------------------------------------------- Durable Object
export class RelayRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, xml TEXT, status TEXT NOT NULL, error TEXT, response TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
    );
    this.sql.exec("CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created_at)");
    // Keep-alive pings from the bridge are answered by the runtime without waking this object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));

    this.lastPollAt = 0; // legacy poller, in memory only
    this.pollWaiters = []; // resolvers of parked long-polls
    this.jobWaiters = new Map(); // jobId -> [resolve]
    this.attempts = new Map(); // admin guard (only used by the "__admin__" object)
  }

  async fetch(request) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case "/push":
        return this.handlePush(request);
      case "/poll":
        return this.handlePoll();
      case "/ws":
        return this.handleWebSocket();
      case "/result": {
        const b = await request.json().catch(() => ({}));
        this.complete(b.jobId, b.status, b.error, b.tallyResponse);
        return Response.json({ success: true });
      }
      case "/status":
        return this.handleStatus(url);
      case "/daemon":
        return Response.json(this.daemonInfo());
      case "/guard/check":
        return this.guard(url.searchParams.get("ip") || "", "check");
      case "/guard/fail":
        return this.guard(url.searchParams.get("ip") || "", "fail");
      default:
        return Response.json({ error: "Not found" }, { status: 404 });
    }
  }

  // ----- online state -----
  liveSockets() {
    return this.ctx.getWebSockets().filter((ws) => ws.readyState === undefined || ws.readyState === 1);
  }

  isOnline() {
    return this.liveSockets().length > 0 || this.pollWaiters.length > 0 || Date.now() - this.lastPollAt < ONLINE_WINDOW_MS;
  }

  daemonInfo() {
    if (this.liveSockets().length > 0 || this.pollWaiters.length > 0) return { online: true, lastSeenSecondsAgo: 0 };
    if (!this.lastPollAt) return { online: false, lastSeenSecondsAgo: null };
    const ago = Math.round((Date.now() - this.lastPollAt) / 1000);
    return { online: ago * 1000 < ONLINE_WINDOW_MS, lastSeenSecondsAgo: ago };
  }

  // ----- jobs -----
  async handlePush(request) {
    const { xml, routeId } = await request.json().catch(() => ({}));
    if (typeof xml !== "string" || !xml || !/^[0-9a-f]{24}$/.test(String(routeId || ""))) {
      return Response.json({ error: "bad request" }, { status: 400 });
    }
    const jobId = `${routeId}.${crypto.randomUUID()}`;
    const now = Date.now();
    this.sql.exec("INSERT INTO jobs (job_id, xml, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)", jobId, xml, now, now);
    await this.armAlarm(30_000);
    const online = this.isOnline();
    this.dispatch();
    return Response.json({ success: true, jobId, bridgeOnline: online });
  }

  claimNext() {
    const rows = this.sql
      .exec(
        "UPDATE jobs SET status = 'in_progress', updated_at = ? WHERE job_id = (SELECT job_id FROM jobs WHERE status = 'pending' ORDER BY created_at LIMIT 1) RETURNING job_id, xml",
        Date.now()
      )
      .toArray();
    return rows.length ? rows[0] : null;
  }

  dispatch() {
    this.expireStale();
    const sockets = this.liveSockets();
    if (sockets.length > 0) {
      const ws = sockets[sockets.length - 1];
      let job;
      while ((job = this.claimNext())) {
        try {
          ws.send(JSON.stringify({ type: "job", jobId: job.job_id, xml: job.xml }));
        } catch (_) {
          this.sql.exec("UPDATE jobs SET status = 'pending', updated_at = ? WHERE job_id = ?", Date.now(), job.job_id);
          break;
        }
      }
      return;
    }
    const waiter = this.pollWaiters.shift();
    if (waiter) waiter();
  }

  expireStale() {
    const now = Date.now();
    const dropped = this.sql
      .exec(
        "UPDATE jobs SET status = 'expired', xml = NULL, error = ?, updated_at = ? WHERE status = 'pending' AND created_at < ? RETURNING job_id",
        "The job was not picked up: tally-bridge.exe is offline. Start it on the shop PC and open the company in Tally.",
        now,
        now - PENDING_TTL_MS
      )
      .toArray();
    const stuck = this.sql
      .exec(
        "UPDATE jobs SET status = 'unknown', xml = NULL, error = ?, updated_at = ? WHERE status = 'in_progress' AND updated_at < ? RETURNING job_id",
        "The bridge took this job but never reported a result. Check the Tally Day Book before retrying.",
        now,
        now - INPROGRESS_TTL_MS
      )
      .toArray();
    for (const r of dropped) this.notify(r.job_id);
    for (const r of stuck) this.notify(r.job_id);
  }

  complete(jobId, status, error, response) {
    if (typeof jobId !== "string") return;
    let st = ["success", "tally_rejected", "tally_offline"].includes(status) ? status : "tally_rejected";
    let err = error ? String(error).slice(0, 4000) : null;
    let body = typeof response === "string" ? response : null;
    if (body && enc.encode(body).length > MAX_ROW_BYTES) {
      body = null;
      err = err || "Tally response was too large to relay (over 1.8 MB).";
    }
    this.sql.exec(
      "UPDATE jobs SET status = ?, error = ?, response = ?, xml = NULL, updated_at = ? WHERE job_id = ? AND status IN ('pending', 'in_progress')",
      st,
      err,
      body,
      Date.now(),
      jobId
    );
    this.notify(jobId);
  }

  jobView(jobId) {
    this.expireStale();
    const rows = this.sql.exec("SELECT status, error, response FROM jobs WHERE job_id = ?", jobId).toArray();
    if (!rows.length) return { completed: true, status: "unknown", error: "Job not found (it may have expired)." };
    const j = rows[0];
    if (j.status === "pending" || j.status === "in_progress") return { completed: false, status: j.status };
    if (j.status === "expired") return { completed: true, status: "tally_offline", error: j.error };
    return { completed: true, status: j.status, error: j.error, tallyResponse: j.response };
  }

  async handleStatus(url) {
    const jobId = url.searchParams.get("jobId") || "";
    const waitMs = Math.min(Number(url.searchParams.get("wait")) || 0, MAX_WAIT_S) * 1000;
    let view = this.jobView(jobId);
    if (!view.completed && waitMs > 0) {
      await this.waitForJob(jobId, waitMs);
      view = this.jobView(jobId);
    }
    return Response.json(view);
  }

  waitForJob(jobId, ms) {
    return new Promise((resolve) => {
      const list = this.jobWaiters.get(jobId) || [];
      const timer = setTimeout(() => resolve(), ms);
      list.push(() => {
        clearTimeout(timer);
        resolve();
      });
      this.jobWaiters.set(jobId, list);
    });
  }

  notify(jobId) {
    const list = this.jobWaiters.get(jobId);
    if (!list) return;
    this.jobWaiters.delete(jobId);
    for (const fn of list) fn();
  }

  // ----- old bridge: long-poll -----
  async handlePoll() {
    this.lastPollAt = Date.now();
    this.expireStale();
    let job = this.claimNext();
    if (!job) {
      await new Promise((resolve) => {
        let timer;
        const done = () => {
          clearTimeout(timer);
          const i = this.pollWaiters.indexOf(done);
          if (i >= 0) this.pollWaiters.splice(i, 1);
          resolve();
        };
        timer = setTimeout(done, POLL_HOLD_MS);
        this.pollWaiters.push(done);
      });
      this.lastPollAt = Date.now();
      job = this.claimNext();
    }
    if (!job) return Response.json({ pending: false });
    return Response.json({ pending: true, jobId: job.job_id, data: { xml: job.xml } });
  }

  // ----- new bridge: hibernating WebSocket -----
  handleWebSocket() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    for (const old of this.ctx.getWebSockets()) {
      try {
        old.close(1000, "replaced by a newer bridge connection");
      } catch (_) {}
    }
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "hello" }));
    this.dispatch(); // deliver anything that queued while the bridge was reconnecting
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string") return;
    let m;
    try {
      m = JSON.parse(message);
    } catch (_) {
      return;
    }
    if (m && m.type === "result" && typeof m.jobId === "string") {
      this.complete(m.jobId, m.status, m.error, m.tallyResponse);
    }
  }

  async webSocketClose(ws, code) {
    try {
      ws.close(code && code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000);
    } catch (_) {}
  }

  async webSocketError() {}

  // ----- housekeeping -----
  async armAlarm(ms) {
    const cur = await this.ctx.storage.getAlarm();
    const at = Date.now() + ms;
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  async alarm() {
    this.expireStale();
    this.sql.exec("DELETE FROM jobs WHERE status NOT IN ('pending', 'in_progress') AND updated_at < ?", Date.now() - RESULT_KEEP_MS);
    const s = this.sql.exec("SELECT COUNT(*) AS n, COALESCE(SUM(status IN ('pending', 'in_progress')), 0) AS active FROM jobs").toArray()[0];
    if (s && s.n > 0) await this.ctx.storage.setAlarm(Date.now() + (s.active > 0 ? 30_000 : RESULT_KEEP_MS));
  }

  // ----- admin PIN brute-force guard (used by the "__admin__" object; in memory) -----
  guard(ip, action) {
    const now = Date.now();
    const list = (this.attempts.get(ip) || []).filter((t) => now - t < GUARD_WINDOW_MS);
    if (action === "fail") {
      list.push(now);
      if (this.attempts.size > 2000) this.attempts.clear();
      this.attempts.set(ip, list);
      return Response.json({ ok: true });
    }
    return Response.json({ blocked: list.length >= GUARD_MAX_FAILS }, { status: list.length >= GUARD_MAX_FAILS ? 429 : 200 });
  }
}
