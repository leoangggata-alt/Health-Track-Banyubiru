// platform-api/src/routes/admin.ts
// Handlers for School Admin: License enforcement, school management, classes, students, dashboard, and reports

import { sha256, generateSalt, pbkdf2, verifyPassword } from "../crypto.ts";
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

export async function handleAdminRoute(
  request: Request,
  url: URL,
  db: D1Database,
  clientIp: string
): Promise<Response> {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  const json = (data: any, status = 200, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
    });

  const error = (message: string, status = 400, code = "BAD_REQUEST", details: any = null) =>
    json({ ok: false, error: { message, code, details } }, status);

  const todayStr = new Date().toISOString().slice(0, 10);

  // 1. ADMIN LOGIN WITH LICENSE KEY + USERNAME + PASSWORD
  if (path === "/api/admin/login" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const licenseKey = (body.licenseKey || "").trim();
    const username = (body.username || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!licenseKey || !username || !password) {
      return error("Kunci lisensi, username, dan password wajib diisi.", 400, "MISSING_FIELDS");
    }

    const rateKey = `admin_login:${clientIp}:${username}`;
    const rateCheck = await checkRateLimit(db, rateKey, 5, 15);
    if (!rateCheck.allowed) {
      return error(
        `Terlalu banyak percobaan gagal. Silakan coba lagi dalam ${Math.ceil((rateCheck.waitSeconds || 60) / 60)} menit.`,
        429,
        "RATE_LIMITED"
      );
    }

    // Verify License Key Hash
    const keyHash = await sha256(licenseKey);
    const license: any = await db
      .prepare("SELECT * FROM licenses WHERE key_hash = ?")
      .bind(keyHash)
      .first();

    if (!license) {
      await recordFailedAttempt(db, rateKey);
      return error("Kunci lisensi tidak valid atau tidak terdaftar.", 401, "INVALID_LICENSE");
    }

    if (license.status === "revoked") {
      return error(
        license.revoke_reason
          ? `Lisensi sekolah telah dicabut: ${license.revoke_reason}`
          : "Lisensi sekolah telah dicabut oleh super admin.",
        403,
        "LICENSE_REVOKED"
      );
    }

    if (license.expires_at < todayStr) {
      return error(
        `Masa berlaku lisensi telah berakhir pada ${license.expires_at}. Hubungi pengelola untuk perpanjangan.`,
        403,
        "LICENSE_EXPIRED"
      );
    }

    // Verify Admin User in that School
    const adminUser: any = await db
      .prepare(
        "SELECT * FROM admin_users WHERE school_id = ? AND username = ? AND status = 'active'"
      )
      .bind(license.school_id, username)
      .first();

    if (!adminUser) {
      await recordFailedAttempt(db, rateKey);
      return error("Username atau password salah.", 401, "INVALID_CREDENTIALS");
    }

    const passValid = await verifyPassword(password, adminUser.password_salt, adminUser.password_hash);
    if (!passValid) {
      await recordFailedAttempt(db, rateKey);
      return error("Username atau password salah.", 401, "INVALID_CREDENTIALS");
    }

    // Clear failed attempts & create session
    await clearFailedAttempts(db, rateKey);
    const { token, csrfToken } = await createSession(db, "admin", adminUser.id, license.school_id);

    const school: any = await db.prepare("SELECT * FROM schools WHERE id = ?").bind(license.school_id).first();
    await logAudit(
      db,
      "admin",
      adminUser.id,
      adminUser.username,
      "admin.login.success",
      school?.id,
      school?.name,
      null,
      clientIp
    );

    return json(
      {
        ok: true,
        session: {
          csrfToken,
          mustChangePassword: Boolean(adminUser.must_change_password),
          admin: { id: adminUser.id, username: adminUser.username },
          school: { id: school?.id, code: school?.code, name: school?.name },
        },
      },
      200,
      { "Set-Cookie": createCookie("vitaqu_admin_session", token) }
    );
  }

  // 2. SESSION CHECK
  if (path === "/api/admin/session" && method === "GET") {
    const sessionData = await getSession(db, request, "admin");
    if (!sessionData) {
      return error("Sesi tidak ditemukan atau telah kedaluwarsa.", 401, "UNAUTHORIZED");
    }

    // Strictly enforce license status on session check
    if (sessionData.isLicenseBlocked) {
      const isRevoked = sessionData.license?.status === "revoked";
      return error(
        sessionData.blockReason || "Akses lisensi ditolak.",
        403,
        isRevoked ? "LICENSE_REVOKED" : "LICENSE_EXPIRED"
      );
    }

    const expDate = new Date(sessionData.license.expires_at);
    const diffDays = Math.ceil((expDate.getTime() - Date.now()) / (1000 * 3600 * 24));

    return json({
      ok: true,
      authenticated: true,
      csrfToken: sessionData.session.csrf_token,
      mustChangePassword: Boolean(sessionData.user.must_change_password),
      admin: {
        id: sessionData.user.id,
        username: sessionData.user.username,
        mustChangePassword: Boolean(sessionData.user.must_change_password),
      },
      school: {
        id: sessionData.school.id,
        code: sessionData.school.code,
        name: sessionData.school.name,
        level: sessionData.school.level,
        principalName: sessionData.school.principal_name,
        city: sessionData.school.city,
      },
      license: {
        validFrom: sessionData.license.valid_from,
        expiresAt: sessionData.license.expires_at,
        status: sessionData.license.status,
        daysRemaining: Math.max(0, diffDays),
      },
    });
  }

  // 3. LOGOUT
  if (path === "/api/admin/logout" && method === "POST") {
    const sessionData = await getSession(db, request, "admin");
    if (sessionData) {
      await deleteSession(db, request, "admin");
      await logAudit(
        db,
        "admin",
        sessionData.user.id,
        sessionData.user.username,
        "admin.logout",
        sessionData.school?.id,
        sessionData.school?.name,
        null,
        clientIp
      );
    }
    return json({ ok: true, message: "Berhasil keluar." }, 200, {
      "Set-Cookie": clearCookie("vitaqu_admin_session"),
    });
  }

  // Check authenticated session for all operations below
  const sessionData = await getSession(db, request, "admin");
  if (!sessionData) {
    return error("Sesi admin tidak aktif atau telah kedaluwarsa.", 401, "UNAUTHORIZED");
  }

  // Enforce license validity: Any access to school data requires active license!
  if (sessionData.isLicenseBlocked) {
    const isRevoked = sessionData.license?.status === "revoked";
    return error(
      sessionData.blockReason || "Lisensi sekolah tidak aktif.",
      403,
      isRevoked ? "LICENSE_REVOKED" : "LICENSE_EXPIRED"
    );
  }

  // CSRF validation for mutating methods
  if (!validateCsrf(request, sessionData.session)) {
    return error("Token keamanan CSRF tidak valid.", 403, "CSRF_ERROR");
  }

  const schoolId = sessionData.school.id;

  // 4. CHANGE PASSWORD
  if (path === "/api/admin/change-password" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const currentPassword = String(body.currentPassword || "");
    const newPassword = String(body.newPassword || "");

    if (!currentPassword || !newPassword) {
      return error("Password saat ini dan password baru wajib diisi.");
    }
    if (newPassword.length < 12) {
      return error("Password baru minimal 12 karakter.");
    }

    // Verify current password
    const userRow: any = await db
      .prepare("SELECT * FROM admin_users WHERE id = ?")
      .bind(sessionData.user.id)
      .first();

    const passValid = await verifyPassword(currentPassword, userRow.password_salt, userRow.password_hash);
    if (!passValid) {
      return error("Password saat ini tidak sesuai.", 401, "INVALID_PASSWORD");
    }

    const salt = generateSalt();
    const newHash = await pbkdf2(newPassword, salt);
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        `UPDATE admin_users SET password_hash = ?, password_salt = ?, must_change_password = 0, updated_at = ? WHERE id = ?`
      )
      .bind(newHash, salt, nowIso, sessionData.user.id)
      .run();

    await logAudit(
      db,
      "admin",
      sessionData.user.id,
      sessionData.user.username,
      "admin.change_password",
      schoolId,
      sessionData.school.name,
      null,
      clientIp
    );

    return json({ ok: true, message: "Password berhasil diperbarui." });
  }

  // 5. SCHOOL INFO & UPDATE
  if (path === "/api/admin/school") {
    if (method === "GET") {
      return json({
        ok: true,
        school: {
          id: sessionData.school.id,
          code: sessionData.school.code,
          name: sessionData.school.name,
          level: sessionData.school.level,
          principalName: sessionData.school.principal_name,
          city: sessionData.school.city,
        },
      });
    }
    if (method === "PATCH") {
      const body: any = await request.json().catch(() => ({}));
      const name = (body.name || sessionData.school.name).trim();
      const level = (body.level || sessionData.school.level).trim();
      const principalName = (body.principalName || sessionData.school.principal_name).trim();
      const city = body.city !== undefined ? body.city.trim() : (sessionData.school.city || "");
      const nowIso = new Date().toISOString();

      await db
        .prepare(
          `UPDATE schools SET name = ?, level = ?, principal_name = ?, city = ?, updated_at = ? WHERE id = ?`
        )
        .bind(name, level, principalName, city, nowIso, schoolId)
        .run();

      await logAudit(
        db,
        "admin",
        sessionData.user.id,
        sessionData.user.username,
        "school.update",
        schoolId,
        name,
        { name, level, principalName, city },
        clientIp
      );

      return json({ ok: true, school: { id: schoolId, name, level, principalName, city } });
    }
  }

  // 6. CLASSES CRUD
  if (path === "/api/admin/classes") {
    if (method === "GET") {
      const { results } = await db
        .prepare("SELECT * FROM classes WHERE school_id = ? AND status != 'archived' ORDER BY name ASC")
        .bind(schoolId)
        .all();
      return json({ ok: true, items: results || [] });
    }
    if (method === "POST") {
      const body: any = await request.json().catch(() => ({}));
      const name = (body.name || "").trim();
      if (!name) return error("Nama kelas wajib diisi.");

      const id = crypto.randomUUID();
      const nowIso = new Date().toISOString();
      await db
        .prepare(
          `INSERT INTO classes (id, school_id, name, status, created_at, updated_at)
           VALUES (?, ?, ?, 'active', ?, ?)`
        )
        .bind(id, schoolId, name, nowIso, nowIso)
        .run();

      return json({ ok: true, class: { id, name } });
    }
  }

  const classItemMatch = path.match(/^\/api\/admin\/classes\/([^/]+)$/);
  if (classItemMatch) {
    const classId = classItemMatch[1];
    if (method === "PATCH") {
      const body: any = await request.json().catch(() => ({}));
      const name = (body.name || "").trim();
      if (!name) return error("Nama kelas tidak boleh kosong.");
      const nowIso = new Date().toISOString();
      await db
        .prepare("UPDATE classes SET name = ?, updated_at = ? WHERE id = ? AND school_id = ?")
        .bind(name, nowIso, classId, schoolId)
        .run();
      return json({ ok: true, message: "Nama kelas diperbarui." });
    }
    if (method === "DELETE") {
      const nowIso = new Date().toISOString();
      await db
        .prepare("UPDATE classes SET status = 'archived', updated_at = ? WHERE id = ? AND school_id = ?")
        .bind(nowIso, classId, schoolId)
        .run();
      return json({ ok: true, message: "Kelas diarsipkan." });
    }
  }

  // 7. STUDENTS CRUD
  if (path === "/api/admin/students") {
    if (method === "GET") {
      const { results } = await db
        .prepare(
          `SELECT st.id, st.student_id, st.name, st.class_id, st.status, c.name as class_name
           FROM students st
           LEFT JOIN classes c ON st.class_id = c.id
           WHERE st.school_id = ?
           ORDER BY c.name ASC, st.name ASC`
        )
        .bind(schoolId)
        .all();

      const items = (results || []).map((row: any) => ({
        id: row.id,
        studentId: row.student_id,
        name: row.name,
        classId: row.class_id,
        className: row.class_name || "-",
        status: row.status,
      }));

      return json({ ok: true, items });
    }
    if (method === "POST") {
      const body: any = await request.json().catch(() => ({}));
      const studentId = (body.studentId || "").trim();
      const name = (body.name || "").trim();
      const classId = (body.classId || "").trim();
      const rawPin = String(body.pin || "1234").trim();

      if (!studentId || !name || !classId) {
        return error("ID siswa, nama siswa, dan kelas wajib dipilih.");
      }

      // Check duplicate studentId in this school
      const existing: any = await db
        .prepare("SELECT id FROM students WHERE school_id = ? AND student_id = ?")
        .bind(schoolId, studentId)
        .first();
      if (existing) {
        return error(`ID siswa "${studentId}" sudah terdaftar di sekolah ini.`, 409, "DUPLICATE_STUDENT");
      }

      const salt = generateSalt();
      const pinHash = await pbkdf2(rawPin, salt);
      const id = crypto.randomUUID();
      const nowIso = new Date().toISOString();

      await db
        .prepare(
          `INSERT INTO students (id, school_id, class_id, student_id, name, pin_hash, pin_salt, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
        )
        .bind(id, schoolId, classId, studentId, name, pinHash, salt, nowIso, nowIso)
        .run();

      return json({ ok: true, student: { id, studentId, name, classId } });
    }
  }

  const studentResetPinMatch = path.match(/^\/api\/admin\/students\/([^/]+)\/reset-pin$/);
  if (studentResetPinMatch && method === "POST") {
    const id = studentResetPinMatch[1];
    const body: any = await request.json().catch(() => ({}));
    const rawPin = String(body.pin || "1234").trim();
    const salt = generateSalt();
    const pinHash = await pbkdf2(rawPin, salt);
    const nowIso = new Date().toISOString();

    await db
      .prepare(
        "UPDATE students SET pin_hash = ?, pin_salt = ?, updated_at = ? WHERE id = ? AND school_id = ?"
      )
      .bind(pinHash, salt, nowIso, id, schoolId)
      .run();

    return json({ ok: true, message: "PIN siswa berhasil direset." });
  }

  const studentItemMatch = path.match(/^\/api\/admin\/students\/([^/]+)$/);
  if (studentItemMatch && method === "PATCH") {
    const id = studentItemMatch[1];
    const body: any = await request.json().catch(() => ({}));
    const status = body.status === "inactive" ? "inactive" : "active";
    const nowIso = new Date().toISOString();
    await db
      .prepare("UPDATE students SET status = ?, updated_at = ? WHERE id = ? AND school_id = ?")
      .bind(status, nowIso, id, schoolId)
      .run();
    return json({ ok: true, message: "Status siswa diperbarui." });
  }

  // 8. PROGRAMS CRUD
  if (path === "/api/admin/programs") {
    if (method === "GET") {
      const { results } = await db
        .prepare("SELECT * FROM programs WHERE school_id = ? ORDER BY start_date DESC")
        .bind(schoolId)
        .all();
      return json({ ok: true, items: results || [] });
    }
    if (method === "POST") {
      const body: any = await request.json().catch(() => ({}));
      const name = (body.name || "").trim();
      const academicYear = (body.academicYear || "").trim();
      const startDate = (body.startDate || "").trim();
      const endDate = (body.endDate || "").trim();
      const status = (body.status || "draft").trim();

      if (!name || !startDate || !endDate) {
        return error("Nama program, tanggal mulai, dan tanggal selesai wajib diisi.");
      }

      const id = crypto.randomUUID();
      const nowIso = new Date().toISOString();

      await db
        .prepare(
          `INSERT INTO programs (id, school_id, name, academic_year, start_date, end_date, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(id, schoolId, name, academicYear, startDate, endDate, status, nowIso, nowIso)
        .run();

      return json({ ok: true, program: { id, name, status } });
    }
  }

  // 8b. RESTART 30-DAY PROGRAM CYCLE (PER SCHOOL LICENSE)
  if (path === "/api/admin/programs/restart" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const rawStartDate = (body.startDate || todayStr).trim();
    const name = (body.name || "Program 30 Hari Hidup Sehat").trim();
    const academicYear = (body.academicYear || "2026/2027").trim();

    if (!/^\d{4}-\d{2}-\d{2}$/.test(rawStartDate)) {
      return error("Format tanggal mulai tidak valid (wajib YYYY-MM-DD).", 400);
    }

    // End date = startDate + 29 days (30 days total)
    const startDateObj = new Date(rawStartDate + "T00:00:00Z");
    const endDateObj = new Date(startDateObj.getTime() + 29 * 24 * 3600 * 1000);
    const rawEndDate = endDateObj.toISOString().slice(0, 10);

    const nowIso = new Date().toISOString();
    const newProgramId = crypto.randomUUID();

    // Archive previous active programs for this school
    await db
      .prepare("UPDATE programs SET status = 'archived', updated_at = ? WHERE school_id = ? AND status = 'active'")
      .bind(nowIso, schoolId)
      .run();

    // Insert newly restarted active program
    await db
      .prepare(
        `INSERT INTO programs (id, school_id, name, academic_year, start_date, end_date, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(newProgramId, schoolId, name, academicYear, rawStartDate, rawEndDate, nowIso, nowIso)
      .run();

    await logAudit(
      db,
      "admin",
      sessionData.user.id,
      sessionData.user.username,
      "program.restart",
      schoolId,
      sessionData.school?.name,
      JSON.stringify({ programId: newProgramId, name, startDate: rawStartDate, endDate: rawEndDate }),
      clientIp
    );

    const todayObj = new Date(todayStr + "T00:00:00Z");
    const diffDays = Math.floor((todayObj.getTime() - startDateObj.getTime()) / (24 * 3600 * 1000)) + 1;
    const currentDay = Math.max(1, Math.min(diffDays, 30));

    return json({
      ok: true,
      message: `Program 30 Hari berhasil di-restart mulai tanggal ${rawStartDate} (Hari ke-${currentDay}/30).`,
      program: {
        id: newProgramId,
        name,
        academicYear,
        startDate: rawStartDate,
        endDate: rawEndDate,
        status: "active",
        day: currentDay,
        durationDays: 30,
      },
    });
  }

  // 8c. GET ACTIVE PROGRAM (PER SCHOOL LICENSE)
  if (path === "/api/admin/programs/active" && method === "GET") {
    const activeProgram: any = await db
      .prepare("SELECT * FROM programs WHERE school_id = ? AND status = 'active' ORDER BY start_date DESC LIMIT 1")
      .bind(schoolId)
      .first();

    if (!activeProgram) {
      return json({
        ok: true,
        program: {
          id: "default",
          name: "Program 30 Hari Hidup Sehat",
          startDate: "2026-11-18",
          endDate: "2026-12-17",
          academicYear: "2026/2027",
          status: "active",
          day: Math.max(1, Math.min(Math.floor((new Date(todayStr + "T00:00:00Z").getTime() - new Date("2026-11-18T00:00:00Z").getTime()) / 86400000) + 1, 30)),
          durationDays: 30,
        },
      });
    }

    const startObj = new Date(activeProgram.start_date + "T00:00:00Z");
    const todayObj = new Date(todayStr + "T00:00:00Z");
    const diff = Math.floor((todayObj.getTime() - startObj.getTime()) / 86400000) + 1;
    const currentDay = Math.max(1, Math.min(diff, 30));

    return json({
      ok: true,
      program: {
        id: activeProgram.id,
        name: activeProgram.name,
        startDate: activeProgram.start_date,
        endDate: activeProgram.end_date,
        academicYear: activeProgram.academic_year,
        status: activeProgram.status,
        day: currentDay,
        durationDays: 30,
        daysLeft: Math.max(0, 30 - currentDay),
      },
    });
  }

  const programItemMatch = path.match(/^\/api\/admin\/programs\/([^/]+)$/);
  if (programItemMatch && method === "PATCH") {
    const id = programItemMatch[1];
    const body: any = await request.json().catch(() => ({}));
    const status = (body.status || "active").trim();
    const nowIso = new Date().toISOString();
    await db
      .prepare("UPDATE programs SET status = ?, updated_at = ? WHERE id = ? AND school_id = ?")
      .bind(status, nowIso, id, schoolId)
      .run();
    return json({ ok: true, message: "Status program diperbarui." });
  }

  // 9. DASHBOARD STATS
  if (path === "/api/admin/dashboard" && method === "GET") {
    const filterDate = url.searchParams.get("date") || todayStr;
    const classId = url.searchParams.get("classId") || "";

    // Total active students
    let totalStudentSql = "SELECT COUNT(*) as total FROM students WHERE school_id = ? AND status = 'active'";
    const totalStudentParams: any[] = [schoolId];
    if (classId) {
      totalStudentSql += " AND class_id = ?";
      totalStudentParams.push(classId);
    }
    const totalStudentRes: any = await db.prepare(totalStudentSql).bind(...totalStudentParams).first();
    const totalStudents = totalStudentRes?.total || 0;

    // Submissions for date
    let subSql = `
      SELECT sub.*, st.name as student_name, st.student_id as student_code, c.name as class_name
      FROM submissions sub
      JOIN students st ON sub.student_id = st.id
      JOIN classes c ON st.class_id = c.id
      WHERE sub.school_id = ? AND sub.date = ?
    `;
    const subParams: any[] = [schoolId, filterDate];
    if (classId) {
      subSql += " AND st.class_id = ?";
      subParams.push(classId);
    }
    const { results: subRows } = await db.prepare(subSql).bind(...subParams).all();
    const submittedCount = (subRows || []).length;
    const notSubmittedCount = Math.max(0, totalStudents - submittedCount);
    const submitPercentage = totalStudents > 0 ? Math.round((submittedCount / totalStudents) * 100) : 0;

    let totalScore = 0;
    (subRows || []).forEach((row: any) => {
      totalScore += row.score || 0;
    });
    const avgScore = submittedCount > 0 ? Math.round(totalScore / submittedCount) : 0;

    // Top students on that date
    const topStudents = (subRows || [])
      .slice()
      .sort((a: any, b: any) => (b.score || 0) - (a.score || 0))
      .slice(0, 5)
      .map((r: any) => ({
        studentId: r.student_code,
        name: r.student_name,
        className: r.class_name,
        score: r.score,
      }));

    // Daily score trends (last 7 days)
    const dailyScores: { date: string; avgScore: number; submittedCount: number }[] = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 24 * 3600 * 1000).toISOString().slice(0, 10);
      dailyScores.push({ date: d, avgScore: d === filterDate ? avgScore : 0, submittedCount: d === filterDate ? submittedCount : 0 });
    }

    // Active program for this school
    const activeProgram: any = await db
      .prepare("SELECT * FROM programs WHERE school_id = ? AND status = 'active' ORDER BY start_date DESC LIMIT 1")
      .bind(schoolId)
      .first();

    let programData: any = null;
    if (activeProgram) {
      const startObj = new Date(activeProgram.start_date + "T00:00:00Z");
      const filterDateObj = new Date(filterDate + "T00:00:00Z");
      const diff = Math.floor((filterDateObj.getTime() - startObj.getTime()) / (24 * 3600 * 1000)) + 1;
      const currentDay = Math.max(1, Math.min(diff, 30));
      programData = {
        id: activeProgram.id,
        name: activeProgram.name,
        startDate: activeProgram.start_date,
        endDate: activeProgram.end_date,
        academicYear: activeProgram.academic_year,
        status: activeProgram.status,
        day: currentDay,
        durationDays: 30,
        daysLeft: Math.max(0, 30 - currentDay),
      };
    } else {
      programData = {
        id: "default",
        name: "Program 30 Hari Hidup Sehat",
        startDate: "2026-11-18",
        endDate: "2026-12-17",
        academicYear: "2026/2027",
        status: "active",
        day: Math.max(1, Math.min(Math.floor((new Date(filterDate + "T00:00:00Z").getTime() - new Date("2026-11-18T00:00:00Z").getTime()) / 86400000) + 1, 30)),
        durationDays: 30,
        daysLeft: 24,
      };
    }

    return json({
      ok: true,
      totalStudents,
      submittedCount,
      notSubmittedCount,
      submitPercentage,
      avgScore,
      programStatus: activeProgram ? "Aktif" : "Perlu Aktivasi",
      program: programData,
      programDay: programData.day,
      programDuration: 30,
      submissions: subRows || [],
      topStudents,
      dailyScores,
    });
  }

  // 10. REPORTS
  if (path === "/api/admin/reports" && method === "GET") {
    const classId = url.searchParams.get("classId") || "";
    const startDate = url.searchParams.get("startDate") || todayStr;
    const endDate = url.searchParams.get("endDate") || todayStr;

    let sql = `
      SELECT sub.*, st.name as student_name, st.student_id as student_code, c.name as class_name
      FROM submissions sub
      JOIN students st ON sub.student_id = st.id
      JOIN classes c ON st.class_id = c.id
      WHERE sub.school_id = ? AND sub.date >= ? AND sub.date <= ?
    `;
    const params: any[] = [schoolId, startDate, endDate];
    if (classId) {
      sql += " AND st.class_id = ?";
      params.push(classId);
    }
    sql += " ORDER BY sub.date DESC, sub.score DESC";

    const { results } = await db.prepare(sql).bind(...params).all();

    return json({
      ok: true,
      school: sessionData.school,
      submissions: results || [],
      generatedAt: todayStr,
      conclusion: "Program hidup sehat berjalan teratur berdasarkan rekapitulasi data server terverifikasi.",
    });
  }

  // 11. ARCHIVE SUBMISSIONS
  if (path === "/api/admin/archive-submissions" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const confirmCode = (body.confirmSchoolCode || "").trim().toUpperCase();
    if (confirmCode !== sessionData.school.code.toUpperCase()) {
      return error("Konfirmasi kode sekolah salah. Penghapusan dibatalkan.", 400, "CONFIRM_FAILED");
    }

    const beforeDate = body.beforeDate || todayStr;
    await db
      .prepare("DELETE FROM submissions WHERE school_id = ? AND date <= ?")
      .bind(schoolId, beforeDate)
      .run();

    await logAudit(
      db,
      "admin",
      sessionData.user.id,
      sessionData.user.username,
      "submissions.archive",
      schoolId,
      sessionData.school.name,
      { beforeDate, reason: body.reason || "Arsip admin" },
      clientIp
    );

    return json({ ok: true, message: "Data pengisian berhasil diarsipkan." });
  }

  return error(`Endpoint "${path}" tidak ditemukan pada Admin.`, 404, "NOT_FOUND");
}
