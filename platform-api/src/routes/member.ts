// platform-api/src/routes/member.ts
// Handlers for Student/Member: School license verification, student registration, submissions, and habits sync

import { sha256 } from "../crypto.ts";
import {
  createSession,
  createCookie,
  clearCookie,
} from "../auth.ts";

export async function handleMemberRoute(
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

  // Helper: Look up school by code or license key and verify license validity
  async function findSchoolByCodeOrKey(rawCode: string) {
    const clean = rawCode.trim();
    if (!clean) return null;

    // 1. Try match by school code (case-insensitive)
    let school: any = await db
      .prepare("SELECT * FROM schools WHERE UPPER(code) = UPPER(?) AND status = 'active'")
      .bind(clean)
      .first();

    // 2. If not found by school code, try match by license key
    if (!school) {
      const keyHash = await sha256(clean);
      const licenseRow: any = await db
        .prepare("SELECT school_id FROM licenses WHERE key_hash = ?")
        .bind(keyHash)
        .first();

      if (licenseRow) {
        school = await db
          .prepare("SELECT * FROM schools WHERE id = ? AND status = 'active'")
          .bind(licenseRow.school_id)
          .first();
      }
    }

    if (!school) return null;

    // Check school license
    const license: any = await db
      .prepare("SELECT * FROM licenses WHERE school_id = ? ORDER BY expires_at DESC LIMIT 1")
      .bind(school.id)
      .first();

    if (!license) {
      return { school, license: null, status: "NO_LICENSE", message: "Sekolah belum memiliki lisensi aktif." };
    }

    if (license.status === "revoked") {
      return {
        school,
        license,
        status: "REVOKED",
        message: license.revoke_reason
          ? `Lisensi sekolah dicabut: ${license.revoke_reason}`
          : "Lisensi sekolah telah dicabut oleh super admin.",
      };
    }

    if (license.expires_at < todayStr) {
      return {
        school,
        license,
        status: "EXPIRED",
        message: `Masa berlaku lisensi sekolah telah berakhir pada ${license.expires_at}.`,
      };
    }

    return { school, license, status: "ACTIVE", message: "Lisensi aktif." };
  }

  // 1. GET SCHOOL PROFILE & CLASSES BY SCHOOL CODE OR LICENSE KEY
  if (path === "/api/member/school" && method === "GET") {
    const code = url.searchParams.get("code") || "";
    if (!code) {
      return error("Kode sekolah atau kunci lisensi wajib diberikan.", 400, "MISSING_CODE");
    }

    const result = await findSchoolByCodeOrKey(code);
    if (!result) {
      return error("Sekolah dengan kode atau kunci lisensi ini tidak ditemukan.", 404, "SCHOOL_NOT_FOUND");
    }

    if (result.status !== "ACTIVE") {
      return error(result.message, 403, `LICENSE_${result.status}`);
    }

    const { school, license } = result;

    // Retrieve active classes for this school
    let { results: classRows } = await db
      .prepare("SELECT id, name FROM classes WHERE school_id = ? AND status = 'active' ORDER BY name ASC")
      .bind(school.id)
      .all();

    // Fallback standard classes if none created yet
    let classes = (classRows || []).map((c: any) => ({ id: c.id, name: c.name }));
    if (classes.length === 0) {
      const defaultNames = ["7A", "7B", "7C", "7D", "7E", "7F", "7G", "8A", "8B", "8C", "8D", "8E", "8F", "8G", "9A", "9B", "9C", "9D", "9E", "9F"];
      classes = defaultNames.map((name) => ({ id: name, name }));
    }

    // Active program
    const activeProgram: any = await db
      .prepare("SELECT id, name, start_date, end_date FROM programs WHERE school_id = ? AND status = 'active' LIMIT 1")
      .bind(school.id)
      .first();

    return json({
      ok: true,
      school: {
        id: school.id,
        code: school.code,
        name: school.name,
        level: school.level,
        principalName: school.principal_name,
        city: school.city,
      },
      license: {
        expiresAt: license.expires_at,
        status: license.status,
      },
      classes,
      program: activeProgram ? {
        id: activeProgram.id,
        name: activeProgram.name,
        startDate: activeProgram.start_date,
        endDate: activeProgram.end_date,
      } : null,
    });
  }

  // 2. MEMBER LOGIN / REGISTRATION
  if (path === "/api/member/login" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const schoolCode = (body.schoolCode || body.code || "").trim();
    const studentName = (body.studentName || body.name || "").trim();
    const classCode = (body.classCode || body.className || "").trim().toUpperCase();

    if (!schoolCode) return error("Kode sekolah atau lisensi wajib diisi.");
    if (!studentName || studentName.length < 3) return error("Nama siswa minimal 3 karakter.");
    if (!classCode) return error("Kelas wajib dipilih.");

    const result = await findSchoolByCodeOrKey(schoolCode);
    if (!result) return error("Sekolah tidak ditemukan.", 404, "SCHOOL_NOT_FOUND");
    if (result.status !== "ACTIVE") return error(result.message, 403, `LICENSE_${result.status}`);

    const { school } = result;

    // Ensure class exists in `classes` table for this school
    let classRow: any = await db
      .prepare("SELECT id, name FROM classes WHERE school_id = ? AND UPPER(name) = ?")
      .bind(school.id, classCode)
      .first();

    if (!classRow) {
      const newClassId = crypto.randomUUID();
      const nowIso = new Date().toISOString();
      await db
        .prepare("INSERT INTO classes (id, school_id, name, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)")
        .bind(newClassId, school.id, classCode, nowIso, nowIso)
        .run();
      classRow = { id: newClassId, name: classCode };
    }

    // Normalized student ID
    const rawStudentCode = studentName.toUpperCase().replace(/\s+/g, " ");

    // Find or create student in this school
    let student: any = await db
      .prepare("SELECT * FROM students WHERE school_id = ? AND UPPER(name) = ?")
      .bind(school.id, rawStudentCode)
      .first();

    const nowIso = new Date().toISOString();
    if (!student) {
      const studentUuid = crypto.randomUUID();
      await db
        .prepare(
          `INSERT INTO students (id, school_id, class_id, student_id, name, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
        )
        .bind(studentUuid, school.id, classRow.id, rawStudentCode, studentName, nowIso, nowIso)
        .run();

      student = {
        id: studentUuid,
        school_id: school.id,
        class_id: classRow.id,
        student_id: rawStudentCode,
        name: studentName,
      };
    } else {
      // Update class if changed
      if (student.class_id !== classRow.id) {
        await db
          .prepare("UPDATE students SET class_id = ?, updated_at = ? WHERE id = ?")
          .bind(classRow.id, nowIso, student.id)
          .run();
        student.class_id = classRow.id;
      }
    }

    // Create opaque member session
    const { token, csrfToken } = await createSession(db, "member" as any, student.id, school.id);

    return json(
      {
        ok: true,
        session: {
          csrfToken,
          student: {
            id: student.id,
            studentCode: student.student_id,
            name: student.name,
            classId: classRow.id,
            classCode: classRow.name,
            schoolId: school.id,
            schoolCode: school.code,
            schoolName: school.name,
          },
        },
      },
      200,
      { "Set-Cookie": createCookie("vitaqu_member_session", token) }
    );
  }

  // 3. GET MEMBER SUBMISSIONS & DATA
  if (path === "/api/member/submissions" && method === "GET") {
    const studentId = url.searchParams.get("studentId") || "";
    const schoolId = url.searchParams.get("schoolId") || "";

    if (!studentId || !schoolId) {
      return error("studentId dan schoolId diperlukan.", 400);
    }

    // Fetch submissions for this student in this school
    const { results } = await db
      .prepare("SELECT date, habits, score, mood, journal, created_at FROM submissions WHERE school_id = ? AND student_id = ? ORDER BY date ASC")
      .bind(schoolId, studentId)
      .all();

    const submissionsMap: Record<string, any> = {};
    for (const row of results || []) {
      let parsedHabits: any = [];
      try { parsedHabits = JSON.parse((row as any).habits); } catch (_) {}
      submissionsMap[(row as any).date] = {
        habits: parsedHabits,
        score: (row as any).score,
        mood: (row as any).mood || "",
        journal: (row as any).journal || "",
      };
    }

    return json({
      ok: true,
      submissions: submissionsMap,
    });
  }

  // 4. SUBMIT / SAVE DAILY CHECKLIST
  if (path === "/api/member/submit" && method === "POST") {
    const body: any = await request.json().catch(() => ({}));
    const schoolId = (body.schoolId || "").trim();
    const studentId = (body.studentId || "").trim();
    const date = (body.date || todayStr).trim();
    const habits = Array.isArray(body.habits) ? body.habits : [];
    const score = Number(body.score) || 0;
    const mood = String(body.mood || "");
    const journal = String(body.journal || "");

    if (!schoolId || !studentId) {
      return error("schoolId dan studentId wajib diisi.");
    }

    // Verify school license is still active
    const license: any = await db
      .prepare("SELECT status, expires_at FROM licenses WHERE school_id = ? ORDER BY expires_at DESC LIMIT 1")
      .bind(schoolId)
      .first();

    if (!license || license.status === "revoked" || license.expires_at < todayStr) {
      return error("Lisensi sekolah telah kedaluwarsa atau dicabut. Pengisian tidak dapat disimpan.", 403, "LICENSE_INACTIVE");
    }

    const habitsJson = JSON.stringify(habits);
    const nowIso = new Date().toISOString();
    const submissionId = crypto.randomUUID();

    // Upsert submission
    await db
      .prepare(
        `INSERT INTO submissions (id, school_id, student_id, date, habits, score, mood, journal, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(student_id, date) DO UPDATE SET
           habits = excluded.habits,
           score = excluded.score,
           mood = excluded.mood,
           journal = excluded.journal,
           updated_at = excluded.updated_at`
      )
      .bind(submissionId, schoolId, studentId, date, habitsJson, score, mood, journal, nowIso, nowIso)
      .run();

    return json({
      ok: true,
      date,
      score,
      message: "Checklist berhasil disimpan ke database sekolah.",
    });
  }

  // 5. MEMBER LOGOUT
  if (path === "/api/member/logout" && method === "POST") {
    return json({ ok: true, message: "Berhasil keluar." }, 200, {
      "Set-Cookie": clearCookie("vitaqu_member_session"),
    });
  }

  return error(`Endpoint "${path}" tidak ditemukan pada Member API.`, 404, "NOT_FOUND");
}
