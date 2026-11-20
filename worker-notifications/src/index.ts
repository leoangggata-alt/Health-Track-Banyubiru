import {
  buildPushPayload,
  type PushSubscription,
} from "@block65/webcrypto-web-push";
import messages from "./messages.json";

type Slot = "morning" | "afternoon" | "evening";
type Role = "student" | "teacher";

type Env = {
  DB: D1Database;
  VAPID_SUBJECT: string;
  VAPID_SERVER_PUBLIC_KEY: string;
  VAPID_SERVER_PRIVATE_KEY: string;
  ALLOWED_ORIGINS: string;
};

type SubscriptionRow = {
  endpoint_hash: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  expiration_time: number | null;
  role: Role;
  morning_enabled: number;
  afternoon_enabled: number;
  evening_enabled: number;
  last_test_at: string | null;
};

type SubscribeBody = {
  subscription?: {
    endpoint?: unknown;
    expirationTime?: unknown;
    keys?: { p256dh?: unknown; auth?: unknown };
  };
  role?: unknown;
  schedules?: { morning?: unknown; afternoon?: unknown; evening?: unknown };
};

const SCHEDULES: Record<string, Slot> = {
  "15 23 * * *": "morning",
  "15 7 * * *": "afternoon",
  "55 13 * * *": "evening",
};

const SLOT_LABELS: Record<Slot, string> = {
  morning: "Pagi • 06.15 WIB",
  afternoon: "Siang • 14.15 WIB",
  evening: "Malam • 20.55 WIB",
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const MAX_BODY_BYTES = 16_384;
const TEST_COOLDOWN_MS = 45_000;

function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function corsHeaders(request: Request, env: Env): HeadersInit | null {
  const origin = request.headers.get("origin");
  if (!origin) return {};

  const exact = new Set(
    (env.ALLOWED_ORIGINS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
  const isPagesPreview = /^https:\/\/[a-z0-9-]+\.health-track-banyubiru\.pages\.dev$/i.test(origin);
  if (!exact.has(origin) && !isPagesPreview) return null;

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

async function readJson<T>(request: Request): Promise<T> {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_BODY_BYTES) throw new Error("Payload terlalu besar");
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    throw new Error("Content-Type harus application/json");
  }
  return request.json<T>();
}

function isSafePushEndpoint(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || value.length > 2048) return false;
    const host = url.hostname.toLowerCase();
    return (
      host === "fcm.googleapis.com" ||
      host === "web.push.apple.com" ||
      host === "push.services.mozilla.com" ||
      host.endsWith(".push.services.mozilla.com") ||
      host === "notify.windows.com" ||
      host.endsWith(".notify.windows.com") ||
      host === "push.microsoft.com" ||
      host.endsWith(".push.microsoft.com")
    );
  } catch {
    return false;
  }
}

function asBoolean(value: unknown, fallback = true): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function validateSubscription(body: SubscribeBody): {
  subscription: PushSubscription;
  role: Role;
  schedules: Record<Slot, boolean>;
} {
  const endpoint = body.subscription?.endpoint;
  const p256dh = body.subscription?.keys?.p256dh;
  const auth = body.subscription?.keys?.auth;
  const expiration = body.subscription?.expirationTime;

  if (typeof endpoint !== "string" || !isSafePushEndpoint(endpoint)) {
    throw new Error("Endpoint push tidak valid");
  }
  if (typeof p256dh !== "string" || p256dh.length < 40 || p256dh.length > 256) {
    throw new Error("Kunci p256dh tidak valid");
  }
  if (typeof auth !== "string" || auth.length < 8 || auth.length > 128) {
    throw new Error("Kunci auth tidak valid");
  }
  if (expiration !== null && expiration !== undefined && !Number.isFinite(expiration)) {
    throw new Error("Waktu kedaluwarsa tidak valid");
  }

  const role: Role = body.role === "teacher" ? "teacher" : "student";
  const schedules = {
    morning: asBoolean(body.schedules?.morning),
    afternoon: asBoolean(body.schedules?.afternoon),
    evening: asBoolean(body.schedules?.evening),
  };

  return {
    subscription: {
      endpoint,
      expirationTime: typeof expiration === "number" ? expiration : null,
      keys: { p256dh, auth },
    },
    role,
    schedules,
  };
}

async function endpointHash(endpoint: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(endpoint));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error("ID subscription tidak valid");
  }
  return value.toLowerCase();
}

function rowToSubscription(row: SubscriptionRow): PushSubscription {
  return {
    endpoint: row.endpoint,
    expirationTime: row.expiration_time,
    keys: { p256dh: row.p256dh, auth: row.auth },
  };
}

function jakartaDate(): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Jakarta",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const value = Object.fromEntries(parts.map(({ type, value }) => [type, value]));
  return `${value.year}-${value.month}-${value.day}`;
}

function deterministicIndex(seed: string, length: number): number {
  let hash = 2166136261;
  for (let index = 0; index < seed.length; index++) {
    hash ^= seed.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % length;
}

function notificationFor(slot: Slot, row: SubscriptionRow, isTest = false) {
  const date = jakartaDate();
  const candidates = messages.filter((message) => message.slot === slot);
  const selected = candidates[deterministicIndex(`${date}|${slot}|${row.endpoint_hash}`, candidates.length)];
  return {
    title: isTest ? "VITAQU • Tes Pengingat Berhasil" : selected.title,
    body: isTest
      ? `Notifikasi aktif. Jadwal pilihanmu akan dikirim pada waktunya. ${selected.body}`
      : selected.body,
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    tag: isTest ? "vitaqu-test" : `vitaqu-${slot}-${date}`,
    renotify: false,
    requireInteraction: false,
    timestamp: Date.now(),
    data: {
      url: `/app.html?from=notification&slot=${slot}`,
      slot,
      slotLabel: SLOT_LABELS[slot],
    },
  };
}

async function sendPush(env: Env, row: SubscriptionRow, slot: Slot, isTest = false): Promise<number> {
  const message = {
    data: JSON.stringify(notificationFor(slot, row, isTest)),
    options: {
      topic: isTest ? "vitaqu-test" : `vitaqu-${slot}`,
      ttl: isTest ? 300 : 3_600,
      urgency: (isTest ? "high" : "normal") as "high" | "normal",
    },
  };
  const payload = await buildPushPayload(message, rowToSubscription(row), {
    subject: env.VAPID_SUBJECT,
    publicKey: env.VAPID_SERVER_PUBLIC_KEY,
    privateKey: env.VAPID_SERVER_PRIVATE_KEY,
  });
  const response = await fetch(row.endpoint, payload);
  return response.status;
}

async function handleSubscribe(request: Request, env: Env, cors: HeadersInit): Promise<Response> {
  const { subscription, role, schedules } = validateSubscription(await readJson<SubscribeBody>(request));
  const id = await endpointHash(subscription.endpoint);

  await env.DB.prepare(`
    INSERT INTO push_subscriptions (
      endpoint_hash, endpoint, p256dh, auth, expiration_time, role,
      morning_enabled, afternoon_enabled, evening_enabled, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(endpoint_hash) DO UPDATE SET
      endpoint = excluded.endpoint,
      p256dh = excluded.p256dh,
      auth = excluded.auth,
      expiration_time = excluded.expiration_time,
      role = excluded.role,
      morning_enabled = excluded.morning_enabled,
      afternoon_enabled = excluded.afternoon_enabled,
      evening_enabled = excluded.evening_enabled,
      updated_at = CURRENT_TIMESTAMP
  `).bind(
    id,
    subscription.endpoint,
    subscription.keys.p256dh,
    subscription.keys.auth,
    subscription.expirationTime,
    role,
    Number(schedules.morning),
    Number(schedules.afternoon),
    Number(schedules.evening),
  ).run();

  return json({ ok: true, id, schedules, role }, 200, cors);
}

async function handleTest(request: Request, env: Env, cors: HeadersInit): Promise<Response> {
  const id = parseId((await readJson<{ id?: unknown }>(request)).id);
  const row = await env.DB.prepare(
    "SELECT * FROM push_subscriptions WHERE endpoint_hash = ?",
  ).bind(id).first<SubscriptionRow>();
  if (!row) return json({ error: "Subscription tidak ditemukan" }, 404, cors);

  if (row.last_test_at) {
    const last = Date.parse(`${row.last_test_at.replace(" ", "T")}Z`);
    const remaining = TEST_COOLDOWN_MS - (Date.now() - last);
    if (remaining > 0) {
      return json({ error: `Tunggu ${Math.ceil(remaining / 1000)} detik sebelum tes lagi` }, 429, cors);
    }
  }

  const status = await sendPush(env, row, "afternoon", true);
  if (status === 404 || status === 410) {
    await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint_hash = ?").bind(id).run();
    return json({ error: "Subscription sudah kedaluwarsa. Aktifkan kembali pengingat." }, 410, cors);
  }
  if (status < 200 || status >= 300) {
    return json({ error: "Layanan push menolak pesan", endpointStatus: status }, 502, cors);
  }

  await env.DB.prepare(
    "UPDATE push_subscriptions SET last_test_at = CURRENT_TIMESTAMP WHERE endpoint_hash = ?",
  ).bind(id).run();
  return json({ ok: true, endpointStatus: status }, 200, cors);
}

async function handleDelete(request: Request, env: Env, cors: HeadersInit): Promise<Response> {
  const id = parseId((await readJson<{ id?: unknown }>(request)).id);
  await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint_hash = ?").bind(id).run();
  return json({ ok: true }, 200, cors);
}

async function handleFetch(request: Request, env: Env): Promise<Response> {
  const cors = corsHeaders(request, env);
  if (cors === null) return json({ error: "Origin tidak diizinkan" }, 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  const { pathname } = new URL(request.url);
  if (request.method !== "GET" && !request.headers.get("origin")) {
    return json({ error: "Origin diperlukan" }, 403, cors);
  }
  try {
    if (request.method === "GET" && pathname === "/v1/health") {
      return json({
        ok: true,
        service: "VITAQU Notifications",
        version: "1.0.0",
        timezone: "Asia/Jakarta",
        schedules: ["06:15", "14:15", "20:55"],
      }, 200, cors);
    }
    if (request.method === "GET" && pathname === "/v1/public-key") {
      return json({ publicKey: env.VAPID_SERVER_PUBLIC_KEY }, 200, cors);
    }
    if (request.method === "POST" && pathname === "/v1/subscriptions") {
      return await handleSubscribe(request, env, cors);
    }
    if (request.method === "POST" && pathname === "/v1/test") {
      return await handleTest(request, env, cors);
    }
    if (request.method === "DELETE" && pathname === "/v1/subscriptions") {
      return await handleDelete(request, env, cors);
    }
    return json({ error: "Not found" }, 404, cors);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Permintaan tidak valid";
    console.error("request_error", { pathname, message });
    return json({ error: message }, 400, cors);
  }
}

async function sendScheduled(env: Env, cron: string): Promise<void> {
  const slot = SCHEDULES[cron];
  if (!slot) {
    console.warn("unknown_cron", cron);
    return;
  }

  const column = `${slot}_enabled`;
  const { results } = await env.DB.prepare(
    `SELECT * FROM push_subscriptions WHERE ${column} = 1 ORDER BY endpoint_hash`,
  ).all<SubscriptionRow>();

  let sent = 0;
  let removed = 0;
  let failed = 0;
  const batchSize = 20;

  for (let start = 0; start < results.length; start += batchSize) {
    const batch = results.slice(start, start + batchSize);
    const outcomes = await Promise.allSettled(
      batch.map(async (row) => ({ row, status: await sendPush(env, row, slot) })),
    );

    for (const outcome of outcomes) {
      if (outcome.status === "rejected") {
        failed++;
        console.error("push_exception", outcome.reason);
        continue;
      }
      const { row, status } = outcome.value;
      if (status === 404 || status === 410) {
        await env.DB.prepare("DELETE FROM push_subscriptions WHERE endpoint_hash = ?")
          .bind(row.endpoint_hash)
          .run();
        removed++;
      } else if (status >= 200 && status < 300) {
        await env.DB.prepare(
          "UPDATE push_subscriptions SET last_sent_at = CURRENT_TIMESTAMP WHERE endpoint_hash = ?",
        ).bind(row.endpoint_hash).run();
        sent++;
      } else {
        failed++;
        console.warn("push_rejected", { id: row.endpoint_hash, status });
      }
    }
  }

  console.log("scheduled_push_complete", {
    cron,
    slot,
    total: results.length,
    sent,
    removed,
    failed,
  });
}

export default {
  fetch: handleFetch,
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(sendScheduled(env, controller.cron));
  },
} satisfies ExportedHandler<Env>;
