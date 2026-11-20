// platform-api/src/auth.ts
// Session management, HttpOnly cookies, CSRF validation, and rate limiting

import { sha256, generateRandomToken, timingSafeEqual } from "./crypto.ts";

export interface Env {
  DB: D1Database;
  PROXY_SECRET?: string;
  ALLOWED_ORIGINS?: string;
}

export function parseCookies(request: Request): Record<string, string> {
  const header = request.headers.get("cookie") || "";
  const cookies: Record<string, string> = {};
  header.split(";").forEach((pair) => {
    const [rawName, ...rawVal] = pair.trim().split("=");
    if (rawName) {
      cookies[rawName] = decodeURIComponent(rawVal.join("="));
    }
  });
  return cookies;
}

export function createCookie(
  name: string,
  value: string,
  maxAge = 7 * 24 * 3600
): string {
  const secure = true;
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; ${
    secure ? "Secure; " : ""
  }SameSite=Lax`;
}

export function clearCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export async function createSession(
  db: D1Database,
  portal: "superadmin" | "admin",
  userId: string,
  schoolId: string | null = null
): Promise<{ token: string; csrfToken: string; expiresAt: number }> {
  const token = generateRandomToken(32);
  const tokenHash = await sha256(token);
  const csrfToken = generateRandomToken(16);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 7 * 24 * 3600; // 7 days

  await db
    .prepare(
      `INSERT INTO sessions (token_hash, portal, user_id, school_id, csrf_token, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(tokenHash, portal, userId, schoolId, csrfToken, expiresAt, now)
    .run();

  return { token, csrfToken, expiresAt };
}

export async function getSession(
  db: D1Database,
  request: Request,
  portal: "superadmin" | "admin"
): Promise<{
  session: any;
  user: any;
  school?: any;
  license?: any;
  isLicenseBlocked?: boolean;
  blockReason?: string;
} | null> {
  const cookieName = portal === "superadmin" ? "vitaqu_super_session" : "vitaqu_admin_session";
  const cookies = parseCookies(request);
  const token = cookies[cookieName];
  if (!token) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const sessionRow: any = await db
    .prepare(
      `SELECT * FROM sessions WHERE token_hash = ? AND portal = ? AND expires_at > ?`
    )
    .bind(tokenHash, portal, now)
    .first();

  if (!sessionRow) return null;

  if (portal === "superadmin") {
    const superAdmin: any = await db
      .prepare(`SELECT id, username, status, created_at FROM super_admins WHERE id = ? AND status = 'active'`)
      .bind(sessionRow.user_id)
      .first();

    if (!superAdmin) return null;
    return {
      session: sessionRow,
      user: superAdmin,
    };
  }

  // School Admin portal
  const adminUser: any = await db
    .prepare(
      `SELECT id, school_id, username, must_change_password, status, created_at
       FROM admin_users WHERE id = ? AND status = 'active'`
    )
    .bind(sessionRow.user_id)
    .first();

  if (!adminUser) return null;

  const school: any = await db
    .prepare(`SELECT * FROM schools WHERE id = ?`)
    .bind(adminUser.school_id)
    .first();

  if (!school) return null;

  // Retrieve license for this school
  const license: any = await db
    .prepare(
      `SELECT * FROM licenses WHERE school_id = ? ORDER BY expires_at DESC LIMIT 1`
    )
    .bind(school.id)
    .first();

  let isLicenseBlocked = false;
  let blockReason = "";

  if (!license) {
    isLicenseBlocked = true;
    blockReason = "Lisensi tidak ditemukan.";
  } else if (license.status === "revoked") {
    isLicenseBlocked = true;
    blockReason = license.revoke_reason
      ? `Lisensi dicabut: ${license.revoke_reason}`
      : "Lisensi sekolah telah dicabut oleh super admin.";
  } else {
    const today = new Date().toISOString().slice(0, 10);
    if (license.expires_at < today) {
      isLicenseBlocked = true;
      blockReason = `Masa berlaku lisensi telah berakhir pada ${license.expires_at}.`;
    }
  }

  return {
    session: sessionRow,
    user: adminUser,
    school,
    license,
    isLicenseBlocked,
    blockReason,
  };
}

export async function deleteSession(
  db: D1Database,
  request: Request,
  portal: "superadmin" | "admin"
): Promise<void> {
  const cookieName = portal === "superadmin" ? "vitaqu_super_session" : "vitaqu_admin_session";
  const cookies = parseCookies(request);
  const token = cookies[cookieName];
  if (!token) return;
  const tokenHash = await sha256(token);
  await db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
}

export function validateCsrf(request: Request, session: { csrf_token: string }): boolean {
  const method = request.method.toUpperCase();
  if (["GET", "HEAD", "OPTIONS"].includes(method)) return true;
  const clientCsrf =
    request.headers.get("x-csrf-token") ||
    request.headers.get("X-CSRF-Token") ||
    "";
  if (!clientCsrf || !session.csrf_token) return false;
  return timingSafeEqual(clientCsrf, session.csrf_token);
}

export async function checkRateLimit(
  db: D1Database,
  key: string,
  maxAttempts = 5,
  windowMinutes = 15
): Promise<{ allowed: boolean; waitSeconds?: number }> {
  const now = Math.floor(Date.now() / 1000);
  const windowSec = windowMinutes * 60;
  const row: any = await db
    .prepare(`SELECT attempts, last_attempt_at FROM login_attempts WHERE key = ?`)
    .bind(key)
    .first();

  if (!row) {
    return { allowed: true };
  }

  if (now - row.last_attempt_at > windowSec) {
    // Window expired, reset
    await db.prepare(`DELETE FROM login_attempts WHERE key = ?`).bind(key).run();
    return { allowed: true };
  }

  if (row.attempts >= maxAttempts) {
    const waitSeconds = windowSec - (now - row.last_attempt_at);
    return { allowed: false, waitSeconds };
  }

  return { allowed: true };
}

export async function recordFailedAttempt(db: D1Database, key: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      `INSERT INTO login_attempts (key, attempts, last_attempt_at)
       VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET attempts = attempts + 1, last_attempt_at = ?`
    )
    .bind(key, now, now)
    .run();
}

export async function clearFailedAttempts(db: D1Database, key: string): Promise<void> {
  await db.prepare(`DELETE FROM login_attempts WHERE key = ?`).bind(key).run();
}

export async function logAudit(
  db: D1Database,
  actorType: "superadmin" | "admin" | "system",
  actorId: string,
  actorName: string,
  action: string,
  schoolId: string | null = null,
  schoolName: string | null = null,
  details: any = null,
  ip: string = ""
): Promise<void> {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO audit_logs (id, actor_type, actor_id, actor_name, action, school_id, school_name, details, ip, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      actorType,
      actorId,
      actorName,
      action,
      schoolId,
      schoolName,
      details ? JSON.stringify(details) : null,
      ip,
      now
    )
    .run();
}
