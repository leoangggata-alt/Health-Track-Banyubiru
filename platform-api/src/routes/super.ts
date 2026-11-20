// platform-api/src/routes/super.ts
// Handlers for Super Admin operations: Auth, Licenses, Schools, Admins, Audit

import {
  sha256,
  generateSalt,
  pbkdf2,
  verifyPassword,
  generateLicenseKey,
  generateInitialPassword,
  generateTotpSecret,
  verifyTotp,
} from "../crypto.ts";
import {
  createSession,
  getSession,
  deleteSession,
  validateCsrf,
  createCookie,
  clearCookie,
  checkRateLimit,
  recordFailedAttempt,
  clearFailedAttempts,
  logAudit,
} from "../auth.ts";

export async function handleSuperRoute(
  request: Request,
  url: URL,
  db: D1Database,
  clientIp: string
): Promise<Response> {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // Helper response
  const json = (data: any, status = 200, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
    });

  const error = (message: string, status = 400, code = "BAD_REQUEST", details: any = null) =>
    json({ ok: false, error: { message, code, details } }, status);

  // 1. BOOTSTRAP (Create initial super admin if none exists)
  if (path === "/api/super/bootstrap" && method === "POST") {
    const existing: any = await db.prepare("SELECT COUNT(*) as count FROM super_admins").first();
    if (existing && existing.count > 0) {
      return error("Platform sudah memiliki super admin. Bootstrap dinonaktifkan.", 403, "BOOTSTRAP_DISABLED");
    }

    const body: any = await request.json().catch(() => ({}));
    const username = (body.username || "superadmin").trim().toLowerCase();
    const rawPassword = body.password || generateInitialPassword(16);
    const salt = generateSalt();
    const passwordHash = await pbkdf2(rawPassword, salt);
    const totpSecret = generateTotpSecret(20);
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    await db
      .prepare(
        `INSERT INTO super_admins (id, username, password_hash, password_salt, totp_secret, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(id, username, passwordHash, salt, totpSecret, now, now)
      .run();

    const totpUri = `otpauth://totp/VITAQU%20Control:${encodeURIComponent(username)}?secret=${totpSecret}&issuer=VITAQU`;

    await logAudit(db, "system", id, username, "super.bootstrap", null, null, { username }, clientIp);

    return json({
      ok: true,
      message: "Super admin berhasil diinisialisasi.",
      credentials: {
        username,
        password: rawPassword,
        totpSecret,
        totpUri,
      },
    });
  }

  // 2. LOGIN
  if (path === "/api/super/login" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const username = (body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    const totp = String(body.totp || "").trim();

    if (!username || !password || !totp) {
      return error("Username, password, dan kode autentikator wajib diisi.");
    }

    const rateKey = `super_login:${clientIp}:${username}`;
    const rateCheck = await checkRateLimit(db, rateKey, 5, 15);
    if (!rateCheck.allowed) {
      return error(
        `Terlalu banyak percobaan login gagal. Coba lagi dalam ${Math.ceil((rateCheck.waitSeconds || 60) / 60)} menit.`,
        429,
        "RATE_LIMITED"
      );
    }

    const admin: any = await db
      .prepare("SELECT * FROM super_admins WHERE username = ? AND status = 'active'")
      .bind(username)
      .first();

    if (!admin) {
      await recordFailedAttempt(db, rateKey);
      return error("Kredensial atau kode autentikator tidak valid.", 401, "INVALID_CREDENTIALS");
    }

    const validPass = await verifyPassword(password, admin.password_salt, admin.password_hash);
    if (!validPass) {
      await recordFailedAttempt(db, rateKey);
      return error("Kredensial atau kode autentikator tidak valid.", 401, "INVALID_CREDENTIALS");
    }

    const validTotp = await verifyTotp(admin.totp_secret, totp);
    if (!validTotp) {
      await recordFailedAttempt(db, rateKey);
      return error("Kode autentikator salah atau sudah kedaluwarsa.", 401, "INVALID_TOTP");
    }

    // Login successful
    await clearFailedAttempts(db, rateKey);
    const { token, csrfToken } = await createSession(db, "superadmin", admin.id, null);
    await logAudit(db, "superadmin", admin.id, admin.username, "super.login.success", null, null, null, clientIp);

    return json(
      {
        ok: true,
        session: {
          csrfToken,
          user: { id: admin.id, username: admin.username, role: "superadmin" },
        },
      },
      200,
      { "Set-Cookie": createCookie("vitaqu_super_session", token) }
    );
  }

  // 3. SESSION CHECK
  if (path === "/api/super/session" && method === "GET") {
    const sessionData = await getSession(db, request, "superadmin");
    if (!sessionData) {
      return error("Sesi tidak ditemukan atau telah kedaluwarsa.", 401, "UNAUTHORIZED");
    }
    return json({
      ok: true,
      csrfToken: sessionData.session.csrf_token,
      user: {
        id: sessionData.user.id,
        username: sessionData.user.username,
        role: "superadmin",
      },
    });
  }

  // 4. LOGOUT
  if (path === "/api/super/logout" && method === "POST") {
    const sessionData = await getSession(db, request, "superadmin");
    if (sessionData) {
      await deleteSession(db, request, "superadmin");
      await logAudit(
        db,
        "superadmin",
        sessionData.user.id,
        sessionData.user.username,
        "super.logout",
        null,
        null,
        null,
        clientIp
      );
    }
    return json({ ok: true, message: "Berhasil keluar." }, 200, {
      "Set-Cookie": clearCookie("vitaqu_super_session"),
    });
  }

  // All endpoints below require a valid superadmin session!
  const sessionData = await getSession(db, request, "superadmin");
  if (!sessionData) {
    return error("Sesi super admin tidak aktif atau telah berakhir.", 401, "UNAUTHORIZED");
  }

  // Validate CSRF for mutating methods
  if (!validateCsrf(request, sessionData.session)) {
    return error("Token CSRF tidak valid atau sesi kadaluwarsa.", 403, "CSRF_ERROR");
  }

  // Helper date parsing
  const todayStr = new Date().toISOString().slice(0, 10);

  // 5. LIST LICENSES & STATS
  if (path === "/api/super/licenses" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim().toLowerCase();
    const statusFilter = (url.searchParams.get("status") || "all").trim().toLowerCase();
    const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "30", 10)));
    const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10));

    // Base query
    let sql = `
      SELECT l.*, s.name as school_name, s.code as school_code, s.level as school_level,
             s.principal_name as school_principal, s.city as school_city,
             (SELECT COUNT(*) FROM admin_users au WHERE au.school_id = s.id) as admin_count
      FROM licenses l
      JOIN schools s ON l.school_id = s.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (q) {
      sql += ` AND (LOWER(s.name) LIKE ? OR LOWER(s.code) LIKE ?)`;
      params.push(`%${q}%`, `%${q}%`);
    }

    if (statusFilter === "active") {
      sql += ` AND l.status = 'active' AND l.expires_at >= date('now', '+30 days')`;
    } else if (statusFilter === "expiring") {
      sql += ` AND l.status = 'active' AND l.expires_at >= date('now') AND l.expires_at < date('now', '+30 days')`;
    } else if (statusFilter === "expired") {
      sql += ` AND (l.status = 'expired' OR (l.status = 'active' AND l.expires_at < date('now')))`;
    } else if (statusFilter === "revoked") {
      sql += ` AND l.status = 'revoked'`;
    }

    sql += ` ORDER BY l.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const { results } = await db.prepare(sql).bind(...params).all();

    // Total count for pagination
    let countSql = `
      SELECT COUNT(*) as total
      FROM licenses l
      JOIN schools s ON l.school_id = s.id
      WHERE 1=1
    `;
    const countParams: any[] = [];
    if (q) {
      countSql += ` AND (LOWER(s.name) LIKE ? OR LOWER(s.code) LIKE ?)`;
      countParams.push(`%${q}%`, `%${q}%`);
    }
    if (statusFilter === "active") {
      countSql += ` AND l.status = 'active' AND l.expires_at >= date('now', '+30 days')`;
    } else if (statusFilter === "expiring") {
      countSql += ` AND l.status = 'active' AND l.expires_at >= date('now') AND l.expires_at < date('now', '+30 days')`;
    } else if (statusFilter === "expired") {
      countSql += ` AND (l.status = 'expired' OR (l.status = 'active' AND l.expires_at < date('now')))`;
    } else if (statusFilter === "revoked") {
      countSql += ` AND l.status = 'revoked'`;
    }
    const countRes: any = await db.prepare(countSql).bind(...countParams).first();
    const total = countRes?.total || 0;

    // Summary counts for dashboard
    const allLicenses: any = await db
      .prepare(`SELECT status, expires_at FROM licenses`)
      .all();
    const schoolCountRes: any = await db
      .prepare(`SELECT COUNT(*) as total FROM schools`)
      .first();

    let activeCount = 0;
    let expiringCount = 0;
    let expiredCount = 0;
    let revokedCount = 0;

    const todayDate = new Date();
    for (const lic of allLicenses.results || []) {
      if (lic.status === "revoked") {
        revokedCount++;
      } else {
        const exp = new Date(lic.expires_at);
        const diffDays = Math.ceil((exp.getTime() - todayDate.getTime()) / (1000 * 3600 * 24));
        if (diffDays < 0 || lic.status === "expired") {
          expiredCount++;
        } else if (diffDays <= 30) {
          expiringCount++;
          activeCount++;
        } else {
          activeCount++;
        }
      }
    }

    const items = (results || []).map((row: any) => ({
      license: {
        id: row.id,
        schoolId: row.school_id,
        validFrom: row.valid_from,
        expiresAt: row.expires_at,
        status: row.status,
        maxAdmins: row.max_admins,
        keyPrefix: row.key_prefix,
        revokeReason: row.revoke_reason,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
      school: {
        id: row.school_id,
        code: row.school_code,
        name: row.school_name,
        level: row.school_level,
        principalName: row.school_principal,
        city: row.school_city,
      },
      adminCount: row.admin_count,
    }));

    return json({
      ok: true,
      items,
      pagination: {
        total,
        offset,
        limit,
        hasMore: offset + items.length < total,
      },
      summary: {
        totalSchools: schoolCountRes?.total || 0,
        active: activeCount,
        expiring: expiringCount,
        expired: expiredCount,
        revoked: revokedCount,
      },
    });
  }

  // 6. CREATE LICENSE & SCHOOL
  if (path === "/api/super/licenses" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const schoolName = (body.school_name || "").trim();
    const schoolCode = (body.school_code || "").trim().toUpperCase();
    const schoolLevel = (body.school_level || "SMP").trim().toUpperCase();
    const principalName = (body.principal_name || "").trim();
    const duration = String(body.duration || "365");
    const customExpiresAt = (body.expires_at || "").trim();
    const maxAdmins = Math.max(1, parseInt(body.max_admins || "1", 10));
    const initialAdminUsername = (body.initial_admin_username || "admin").trim().toLowerCase();

    if (!schoolName || !schoolCode) {
      return error("Nama sekolah dan kode sekolah wajib diisi.");
    }
    if (!initialAdminUsername) {
      return error("Username admin pertama wajib diisi.");
    }

    // Check duplicate code
    const existingCode: any = await db
      .prepare("SELECT id FROM schools WHERE code = ?")
      .bind(schoolCode)
      .first();
    if (existingCode) {
      return error(`Kode sekolah "${schoolCode}" sudah digunakan sekolah lain.`, 409, "DUPLICATE_CODE");
    }

    // Calculate dates
    const now = new Date();
    const validFrom = todayStr;
    let expiresAt = "";
    if (duration === "custom" && customExpiresAt) {
      expiresAt = customExpiresAt;
    } else {
      const days = parseInt(duration, 10) || 365;
      const expDate = new Date(now.getTime() + days * 24 * 3600 * 1000);
      expiresAt = expDate.toISOString().slice(0, 10);
    }

    const schoolId = crypto.randomUUID();
    const licenseId = crypto.randomUUID();
    const adminId = crypto.randomUUID();
    const nowIso = now.toISOString();

    // Generate License Key & Hash
    const rawLicenseKey = generateLicenseKey();
    const keyHash = await sha256(rawLicenseKey);
    const keyPrefix = rawLicenseKey.slice(0, 11); // e.g. "VITAQU-XXXX"

    // Generate Admin Initial Password
    const rawAdminPassword = generateInitialPassword(14);
    const adminSalt = generateSalt();
    const adminPassHash = await pbkdf2(rawAdminPassword, adminSalt);

    // Insert School
    await db
      .prepare(
        `INSERT INTO schools (id, code, name, level, principal_name, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(schoolId, schoolCode, schoolName, schoolLevel, principalName, nowIso, nowIso)
      .run();

    // Insert License
    await db
      .prepare(
        `INSERT INTO licenses (id, school_id, key_hash, key_prefix, valid_from, expires_at, status, max_admins, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`
      )
      .bind(licenseId, schoolId, keyHash, keyPrefix, validFrom, expiresAt, maxAdmins, nowIso, nowIso)
      .run();

    // Insert Initial Admin User
    await db
      .prepare(
        `INSERT INTO admin_users (id, school_id, username, password_hash, password_salt, must_change_password, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?)`
      )
      .bind(adminId, schoolId, initialAdminUsername, adminPassHash, adminSalt, nowIso, nowIso)
      .run();

    // Audit logs
    const auditDetails = {
      schoolId,
      schoolCode,
      schoolName,
      licenseId,
      expiresAt,
      maxAdmins,
      initialAdmin: initialAdminUsername,
    };
    await db
      .prepare(
        `INSERT INTO license_audit (id, license_id, actor, action, details, created_at)
         VALUES (?, ?, ?, 'license.create', ?, ?)`
      )
      .bind(crypto.randomUUID(), licenseId, sessionData.user.username, JSON.stringify(auditDetails), nowIso)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "license.create",
      schoolId,
      schoolName,
      auditDetails,
      clientIp
    );

    return json({
      ok: true,
      credentials: {
        licenseKey: rawLicenseKey,
        username: initialAdminUsername,
        initialPassword: rawAdminPassword,
        schoolCode,
        schoolName,
      },
      license: {
        id: licenseId,
        schoolId,
        validFrom,
        expiresAt,
        status: "active",
        maxAdmins,
        keyPrefix,
      },
      school: {
        id: schoolId,
        code: schoolCode,
        name: schoolName,
        level: schoolLevel,
        principalName,
      },
    });
  }

  // 7. GET LICENSE DETAIL
  const licenseDetailMatch = path.match(/^\/api\/super\/licenses\/([^/]+)$/);
  if (licenseDetailMatch && method === "GET") {
    const licenseId = licenseDetailMatch[1];
    const license: any = await db
      .prepare("SELECT * FROM licenses WHERE id = ?")
      .bind(licenseId)
      .first();

    if (!license) return error("Lisensi tidak ditemukan.", 404, "NOT_FOUND");

    const school: any = await db
      .prepare("SELECT * FROM schools WHERE id = ?")
      .bind(license.school_id)
      .first();

    const admins: any = await db
      .prepare("SELECT id, username, status, must_change_password, created_at FROM admin_users WHERE school_id = ?")
      .bind(license.school_id)
      .all();

    const audit: any = await db
      .prepare("SELECT * FROM license_audit WHERE license_id = ? ORDER BY created_at DESC LIMIT 50")
      .bind(licenseId)
      .all();

    return json({
      ok: true,
      license: {
        id: license.id,
        schoolId: license.school_id,
        validFrom: license.valid_from,
        expiresAt: license.expires_at,
        status: license.status,
        maxAdmins: license.max_admins,
        keyPrefix: license.key_prefix,
        revokeReason: license.revoke_reason,
        createdAt: license.created_at,
        updatedAt: license.updated_at,
      },
      school: {
        id: school.id,
        code: school.code,
        name: school.name,
        level: school.level,
        principalName: school.principal_name,
        city: school.city,
      },
      admins: (admins.results || []).map((a: any) => ({
        id: a.id,
        username: a.username,
        status: a.status,
        mustChangePassword: Boolean(a.must_change_password),
        createdAt: a.created_at,
      })),
      licenseAudit: (audit.results || []).map((au: any) => ({
        id: au.id,
        actor: au.actor,
        action: au.action,
        details: au.details ? JSON.parse(au.details) : null,
        createdAt: au.created_at,
      })),
    });
  }

  // 8. EXTEND LICENSE
  const extendMatch = path.match(/^\/api\/super\/licenses\/([^/]+)\/extend$/);
  if (extendMatch && method === "POST") {
    const licenseId = extendMatch[1];
    const license: any = await db
      .prepare("SELECT * FROM licenses WHERE id = ?")
      .bind(licenseId)
      .first();
    if (!license) return error("Lisensi tidak ditemukan.", 404, "NOT_FOUND");

    const body: any = await request.json().catch(() => ({}));
    let newExpiresAt = (body.expires_at || "").trim();

    if (!newExpiresAt) {
      const days = parseInt(body.days || "30", 10);
      const baseDate = new Date(Math.max(Date.now(), new Date(license.expires_at).getTime()));
      const extended = new Date(baseDate.getTime() + days * 24 * 3600 * 1000);
      newExpiresAt = extended.toISOString().slice(0, 10);
    }

    const nowIso = new Date().toISOString();
    await db
      .prepare(
        `UPDATE licenses SET expires_at = ?, status = 'active', updated_at = ? WHERE id = ?`
      )
      .bind(newExpiresAt, nowIso, licenseId)
      .run();

    const details = { oldExpiresAt: license.expires_at, newExpiresAt };
    await db
      .prepare(
        `INSERT INTO license_audit (id, license_id, actor, action, details, created_at)
         VALUES (?, ?, ?, 'license.extend', ?, ?)`
      )
      .bind(crypto.randomUUID(), licenseId, sessionData.user.username, JSON.stringify(details), nowIso)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "license.extend",
      license.school_id,
      null,
      details,
      clientIp
    );

    return json({ ok: true, license: { ...license, expiresAt: newExpiresAt, status: "active" } });
  }

  // 9. REVOKE LICENSE
  const revokeMatch = path.match(/^\/api\/super\/licenses\/([^/]+)\/revoke$/);
  if (revokeMatch && method === "POST") {
    const licenseId = revokeMatch[1];
    const license: any = await db.prepare("SELECT * FROM licenses WHERE id = ?").bind(licenseId).first();
    if (!license) return error("Lisensi tidak ditemukan.", 404, "NOT_FOUND");

    const body: any = await request.json().catch(() => ({}));
    const reason = (body.reason || "Dicabut oleh super admin.").trim();
    const nowIso = new Date().toISOString();

    await db
      .prepare(`UPDATE licenses SET status = 'revoked', revoke_reason = ?, updated_at = ? WHERE id = ?`)
      .bind(reason, nowIso, licenseId)
      .run();

    const details = { reason };
    await db
      .prepare(
        `INSERT INTO license_audit (id, license_id, actor, action, details, created_at)
         VALUES (?, ?, ?, 'license.revoke', ?, ?)`
      )
      .bind(crypto.randomUUID(), licenseId, sessionData.user.username, JSON.stringify(details), nowIso)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "license.revoke",
      license.school_id,
      null,
      details,
      clientIp
    );

    return json({ ok: true, license: { ...license, status: "revoked", revokeReason: reason } });
  }

  // 10. REACTIVATE LICENSE
  const reactivateMatch = path.match(/^\/api\/super\/licenses\/([^/]+)\/reactivate$/);
  if (reactivateMatch && method === "POST") {
    const licenseId = reactivateMatch[1];
    const license: any = await db.prepare("SELECT * FROM licenses WHERE id = ?").bind(licenseId).first();
    if (!license) return error("Lisensi tidak ditemukan.", 404, "NOT_FOUND");

    const body: any = await request.json().catch(() => ({}));
    let newExpiresAt = (body.expires_at || "").trim();
    if (!newExpiresAt && license.expires_at < todayStr) {
      const expDate = new Date(Date.now() + 30 * 24 * 3600 * 1000);
      newExpiresAt = expDate.toISOString().slice(0, 10);
    } else if (!newExpiresAt) {
      newExpiresAt = license.expires_at;
    }

    const nowIso = new Date().toISOString();
    await db
      .prepare(`UPDATE licenses SET status = 'active', revoke_reason = '', expires_at = ?, updated_at = ? WHERE id = ?`)
      .bind(newExpiresAt, nowIso, licenseId)
      .run();

    const details = { expiresAt: newExpiresAt };
    await db
      .prepare(
        `INSERT INTO license_audit (id, license_id, actor, action, details, created_at)
         VALUES (?, ?, ?, 'license.reactivate', ?, ?)`
      )
      .bind(crypto.randomUUID(), licenseId, sessionData.user.username, JSON.stringify(details), nowIso)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "license.reactivate",
      license.school_id,
      null,
      details,
      clientIp
    );

    return json({ ok: true, license: { ...license, status: "active", expiresAt: newExpiresAt } });
  }

  // 11. ADD ADMIN TO LICENSE'S SCHOOL
  const addAdminMatch = path.match(/^\/api\/super\/licenses\/([^/]+)\/admins$/);
  if (addAdminMatch && method === "POST") {
    const licenseId = addAdminMatch[1];
    const license: any = await db.prepare("SELECT * FROM licenses WHERE id = ?").bind(licenseId).first();
    if (!license) return error("Lisensi tidak ditemukan.", 404, "NOT_FOUND");

    // Check admin count against max_admins
    const countRes: any = await db
      .prepare("SELECT COUNT(*) as count FROM admin_users WHERE school_id = ? AND status = 'active'")
      .bind(license.school_id)
      .first();
    if (countRes && countRes.count >= license.max_admins) {
      return error(
        `Batas maksimum admin (${license.max_admins}) untuk sekolah ini sudah tercapai.`,
        400,
        "MAX_ADMINS_REACHED"
      );
    }

    const body: any = await request.json().catch(() => ({}));
    const username = (body.username || "").trim().toLowerCase();
    if (!username) return error("Username admin wajib diisi.");

    // Check duplicate username in this school
    const existing: any = await db
      .prepare("SELECT id FROM admin_users WHERE school_id = ? AND username = ?")
      .bind(license.school_id, username)
      .first();
    if (existing) {
      return error(`Username "${username}" sudah ada di sekolah ini.`, 409, "DUPLICATE_USERNAME");
    }

    const rawPassword = generateInitialPassword(14);
    const salt = generateSalt();
    const passwordHash = await pbkdf2(rawPassword, salt);
    const adminId = crypto.randomUUID();
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        `INSERT INTO admin_users (id, school_id, username, password_hash, password_salt, must_change_password, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?)`
      )
      .bind(adminId, license.school_id, username, passwordHash, salt, nowIso, nowIso)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "admin.create",
      license.school_id,
      null,
      { adminId, username },
      clientIp
    );

    return json({
      ok: true,
      credentials: {
        username,
        initialPassword: rawPassword,
      },
      admin: {
        id: adminId,
        username,
        status: "active",
        mustChangePassword: true,
        createdAt: nowIso,
      },
    });
  }

  // 12. RESET ADMIN PASSWORD
  const resetPassMatch = path.match(/^\/api\/super\/admins\/([^/]+)\/reset-password$/);
  if (resetPassMatch && method === "POST") {
    const adminId = resetPassMatch[1];
    const admin: any = await db.prepare("SELECT * FROM admin_users WHERE id = ?").bind(adminId).first();
    if (!admin) return error("Admin tidak ditemukan.", 404, "NOT_FOUND");

    const rawPassword = generateInitialPassword(14);
    const salt = generateSalt();
    const passwordHash = await pbkdf2(rawPassword, salt);
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        `UPDATE admin_users SET password_hash = ?, password_salt = ?, must_change_password = 1, updated_at = ? WHERE id = ?`
      )
      .bind(passwordHash, salt, nowIso, adminId)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "admin.reset_password",
      admin.school_id,
      null,
      { adminId, username: admin.username },
      clientIp
    );

    return json({
      ok: true,
      credentials: {
        username: admin.username,
        initialPassword: rawPassword,
      },
    });
  }

  // 13. DISABLE ADMIN
  const disableMatch = path.match(/^\/api\/super\/admins\/([^/]+)\/disable$/);
  if (disableMatch && method === "POST") {
    const adminId = disableMatch[1];
    const admin: any = await db.prepare("SELECT * FROM admin_users WHERE id = ?").bind(adminId).first();
    if (!admin) return error("Admin tidak ditemukan.", 404, "NOT_FOUND");

    const nowIso = new Date().toISOString();
    await db
      .prepare(`UPDATE admin_users SET status = 'disabled', updated_at = ? WHERE id = ?`)
      .bind(nowIso, adminId)
      .run();

    await logAudit(
      db,
      "superadmin",
      sessionData.user.id,
      sessionData.user.username,
      "admin.disable",
      admin.school_id,
      null,
      { adminId, username: admin.username },
      clientIp
    );

    return json({ ok: true, message: `Admin ${admin.username} berhasil dinonaktifkan.` });
  }

  // 14. AUDIT LOGS
  if (path === "/api/super/audit" && method === "GET") {
    const action = (url.searchParams.get("action") || "").trim();
    const schoolId = (url.searchParams.get("schoolId") || "").trim();
    const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "30", 10)));
    const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10));

    let sql = "SELECT * FROM audit_logs WHERE 1=1";
    const params: any[] = [];

    if (action && action !== "all") {
      sql += " AND action = ?";
      params.push(action);
    }
    if (schoolId) {
      sql += " AND school_id = ?";
      params.push(schoolId);
    }

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const { results } = await db.prepare(sql).bind(...params).all();

    let countSql = "SELECT COUNT(*) as total FROM audit_logs WHERE 1=1";
    const countParams: any[] = [];
    if (action && action !== "all") {
      countSql += " AND action = ?";
      countParams.push(action);
    }
    if (schoolId) {
      countSql += " AND school_id = ?";
      countParams.push(schoolId);
    }
    const countRes: any = await db.prepare(countSql).bind(...countParams).first();
    const total = countRes?.total || 0;

    const items = (results || []).map((row: any) => ({
      id: row.id,
      actorType: row.actor_type,
      actorId: row.actor_id,
      actor: row.actor_name,
      action: row.action,
      schoolId: row.school_id,
      schoolName: row.school_name,
      details: row.details ? JSON.parse(row.details) : null,
      timestamp: row.created_at,
    }));

    return json({
      ok: true,
      items,
      pagination: {
        total,
        offset,
        limit,
        hasMore: offset + items.length < total,
      },
    });
  }

  return error(`Endpoint "${path}" tidak ditemukan pada Super Admin.`, 404, "NOT_FOUND");
}
