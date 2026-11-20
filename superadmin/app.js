"use strict";

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const STATUS_LABELS = Object.freeze({
    active: "Aktif",
    expiring: "Segera berakhir",
    expired: "Kedaluwarsa",
    revoked: "Dicabut",
    disabled: "Nonaktif",
    unknown: "Tidak diketahui",
  });

  const AUDIT_ACTION_LABELS = Object.freeze({
    "super.login": "Login super admin",
    "super.login.success": "Login super admin",
    "super.logout": "Logout super admin",
    "license.create": "Lisensi dibuat",
    "license.created": "Lisensi dibuat",
    "license.extend": "Lisensi diperpanjang",
    "license.extended": "Lisensi diperpanjang",
    "license.revoke": "Lisensi dicabut",
    "license.revoked": "Lisensi dicabut",
    "license.reactivate": "Lisensi diaktifkan kembali",
    "license.reactivated": "Lisensi diaktifkan kembali",
    "admin.create": "Admin sekolah ditambahkan",
    "admin.created": "Admin sekolah ditambahkan",
    "admin.reset_password": "Password admin direset",
    "admin.password_reset": "Password admin direset",
    "admin.disable": "Admin sekolah dinonaktifkan",
    "admin.disabled": "Admin sekolah dinonaktifkan",
  });

  const state = {
    csrfToken: "",
    user: null,
    currentView: "dashboard",
    dashboardLoaded: false,
    licensesLoaded: false,
    auditLoaded: false,
    dashboardItems: [],
    licenseItems: [],
    licensePagination: { total: 0, offset: 0, limit: 30, hasMore: false },
    licenseRequestId: 0,
    auditItems: [],
    auditActions: new Set(),
    auditPagination: { total: 0, offset: 0, limit: 30, hasMore: false },
    auditRequestId: 0,
    selectedLicenseId: "",
    selectedDetail: null,
    confirmAction: null,
    filterTimer: 0,
    auditSearchTimer: 0,
  };

  class ApiError extends Error {
    constructor(message, { status = 0, code = "REQUEST_FAILED", details = null } = {}) {
      super(message || "Permintaan gagal diproses.");
      this.name = "ApiError";
      this.status = status;
      this.code = code;
      this.details = details;
    }
  }

  /* API contract lives here. Keep UI code independent from route and payload details. */
  const API = Object.freeze({
    login: (credentials) => request("/api/super/login", { method: "POST", body: credentials, csrf: false }),
    session: () => request("/api/super/session", { authFailure: "ignore" }),
    logout: () => request("/api/super/logout", { method: "POST", body: {} }),
    listLicenses: ({ q = "", status = "", expiringWithinDays = "", limit = 30, offset = 0 } = {}) => {
      const query = new URLSearchParams();
      if (q) query.set("q", q);
      if (status) query.set("status", status);
      if (expiringWithinDays !== "") query.set("expiringWithinDays", String(expiringWithinDays));
      query.set("limit", String(limit));
      query.set("offset", String(offset));
      return request(`/api/super/licenses?${query}`);
    },
    createLicense: (payload) => request("/api/super/licenses", { method: "POST", body: payload }),
    getLicense: (licenseId) => request(`/api/super/licenses/${encodeURIComponent(licenseId)}`),
    extendLicense: (licenseId, payload) => request(`/api/super/licenses/${encodeURIComponent(licenseId)}/extend`, { method: "POST", body: payload }),
    revokeLicense: (licenseId, payload) => request(`/api/super/licenses/${encodeURIComponent(licenseId)}/revoke`, { method: "POST", body: payload }),
    reactivateLicense: (licenseId, payload) => request(`/api/super/licenses/${encodeURIComponent(licenseId)}/reactivate`, { method: "POST", body: payload }),
    addAdmin: (licenseId, payload) => request(`/api/super/licenses/${encodeURIComponent(licenseId)}/admins`, { method: "POST", body: payload }),
    resetAdminPassword: (adminId, payload) => request(`/api/super/admins/${encodeURIComponent(adminId)}/reset-password`, { method: "POST", body: payload }),
    disableAdmin: (adminId, payload) => request(`/api/super/admins/${encodeURIComponent(adminId)}/disable`, { method: "POST", body: payload }),
    audit: ({ action = "", schoolId = "", limit = 30, offset = 0 } = {}) => {
      const query = new URLSearchParams();
      if (action) query.set("action", action);
      if (schoolId) query.set("schoolId", schoolId);
      query.set("limit", String(limit));
      query.set("offset", String(offset));
      return request(`/api/super/audit?${query}`);
    },
  });

  async function request(path, { method = "GET", body, csrf = method !== "GET" && method !== "HEAD", authFailure = "expire" } = {}) {
    const headers = new Headers({ Accept: "application/json" });
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (csrf) {
      if (!state.csrfToken) throw new ApiError("Sesi keamanan belum siap. Muat ulang lalu coba lagi.", { code: "CSRF_TOKEN_MISSING" });
      headers.set("x-csrf-token", state.csrfToken);
    }

    let response;
    try {
      response = await fetch(path, {
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError("Tidak dapat terhubung ke layanan VITAQU. Periksa koneksi lalu coba lagi.", { code: "NETWORK_ERROR" });
    }

    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (response.status !== 204) {
      if (contentType.includes("application/json")) {
        try {
          data = await response.json();
        } catch {
          throw new ApiError("Respons layanan tidak valid.", { status: response.status, code: "INVALID_RESPONSE" });
        }
      } else {
        const text = await response.text();
        if (!response.ok) throw new ApiError(text || `Permintaan gagal (${response.status}).`, { status: response.status, code: "HTTP_ERROR" });
        throw new ApiError("Respons layanan bukan JSON.", { status: response.status, code: "INVALID_RESPONSE" });
      }
    }

    if (!response.ok || data?.ok === false) {
      const apiError = data?.error || {};
      const error = new ApiError(apiError.message || `Permintaan gagal (${response.status}).`, {
        status: response.status,
        code: apiError.code || "REQUEST_FAILED",
        details: apiError.details || null,
      });
      if (response.status === 401 && authFailure === "expire") expireSession();
      throw error;
    }

    return data || { ok: true };
  }

  function firstDefined(object, ...keys) {
    if (!object || typeof object !== "object") return undefined;
    for (const key of keys) {
      if (object[key] !== undefined && object[key] !== null) return object[key];
    }
    return undefined;
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function asNumber(value, fallback = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function parseDate(value) {
    if (!value) return null;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    const text = String(value);
    const date = /^\d{4}-\d{2}-\d{2}$/.test(text) ? new Date(`${text}T23:59:59`) : new Date(text);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value, withTime = false) {
    const date = parseDate(value);
    if (!date) return "—";
    return new Intl.DateTimeFormat("id-ID", withTime
      ? { dateStyle: "medium", timeStyle: "short" }
      : { day: "2-digit", month: "short", year: "numeric" }).format(date);
  }

  function dateInputValue(date) {
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 10);
  }

  function tomorrowInputValue() {
    const date = new Date();
    date.setDate(date.getDate() + 1);
    return dateInputValue(date);
  }

  function daysUntil(value) {
    const date = parseDate(value);
    if (!date) return null;
    return Math.ceil((date.getTime() - Date.now()) / 86400000);
  }

  function normalizeLicenseBundle(item) {
    const source = item && typeof item === "object" ? item : {};
    const license = source.license && typeof source.license === "object" ? source.license : source;
    const school = source.school && typeof source.school === "object"
      ? source.school
      : (license.school && typeof license.school === "object" ? license.school : {});
    const adminCount = asNumber(firstDefined(source, "adminCount", "admin_count"), asArray(source.admins).length);
    return { source, license, school, adminCount };
  }

  function licenseId(bundle) {
    return String(firstDefined(bundle?.license, "id", "licenseId", "license_id") || "");
  }

  function schoolId(bundle) {
    return String(firstDefined(bundle?.school, "id", "schoolId", "school_id") || firstDefined(bundle?.license, "schoolId", "school_id") || "");
  }

  function schoolName(bundle) {
    return String(firstDefined(bundle?.school, "name", "schoolName", "school_name") || firstDefined(bundle?.license, "schoolName", "school_name") || "Sekolah tanpa nama");
  }

  function schoolCode(bundle) {
    return String(firstDefined(bundle?.school, "code", "schoolCode", "school_code") || firstDefined(bundle?.license, "schoolCode", "school_code") || "—");
  }

  function licenseExpiry(bundle) {
    return firstDefined(bundle?.license, "expiresAt", "expires_at", "validUntil", "valid_until");
  }

  function licenseStart(bundle) {
    return firstDefined(bundle?.license, "validFrom", "valid_from", "startsAt", "starts_at", "createdAt", "created_at");
  }

  function licenseMaxAdmins(bundle) {
    return asNumber(firstDefined(bundle?.license, "maxAdmins", "max_admins"), 0);
  }

  function licenseStatus(bundle) {
    const raw = String(firstDefined(bundle?.license, "status") || "active").toLowerCase();
    if (["revoked", "revoke", "disabled", "inactive"].includes(raw)) return "revoked";
    if (raw === "expired") return "expired";
    const remaining = daysUntil(licenseExpiry(bundle));
    if (remaining !== null && remaining < 0) return "expired";
    if (remaining !== null && remaining <= 30) return "expiring";
    if (["active", "enabled", "valid"].includes(raw)) return "active";
    return raw || "unknown";
  }

  function normalizeLicenseList(data) {
    const rawItems = asArray(firstDefined(data, "items", "licenses"));
    const items = rawItems.map(normalizeLicenseBundle);
    const rawPagination = firstDefined(data, "pagination") || {};
    const limit = asNumber(firstDefined(rawPagination, "limit"), 30);
    const offset = asNumber(firstDefined(rawPagination, "offset"), 0);
    const total = asNumber(firstDefined(rawPagination, "total", "totalItems", "total_items"), items.length);
    const hasMoreValue = firstDefined(rawPagination, "hasMore", "has_more");
    const hasMore = hasMoreValue === undefined ? offset + items.length < total : Boolean(hasMoreValue);
    return {
      items,
      summary: firstDefined(data, "summary") || {},
      pagination: { limit, offset, total, hasMore },
    };
  }

  function normalizeDetail(data) {
    const bundle = normalizeLicenseBundle({
      license: firstDefined(data, "license") || {},
      school: firstDefined(data, "school") || {},
      adminCount: asArray(firstDefined(data, "admins")).length,
    });
    return {
      bundle,
      admins: asArray(firstDefined(data, "admins")),
      licenseAudit: asArray(firstDefined(data, "licenseAudit", "license_audit")),
    };
  }

  function normalizeAuditResponse(data) {
    const items = asArray(firstDefined(data, "items", "audit", "logs", "auditLogs", "audit_logs"));
    const rawPagination = firstDefined(data, "pagination") || {};
    const limit = asNumber(firstDefined(rawPagination, "limit"), 30);
    const offset = asNumber(firstDefined(rawPagination, "offset"), 0);
    const total = asNumber(firstDefined(rawPagination, "total", "totalItems", "total_items"), items.length);
    const hasMoreValue = firstDefined(rawPagination, "hasMore", "has_more");
    const hasMore = hasMoreValue === undefined ? offset + items.length < total : Boolean(hasMoreValue);
    return { items, pagination: { limit, offset, total, hasMore } };
  }

  function extractSession(data) {
    const session = firstDefined(data, "session") || {};
    const user = firstDefined(data, "user", "superAdmin", "super_admin") || firstDefined(session, "user") || {};
    const csrfToken = String(firstDefined(data, "csrfToken", "csrf_token") || firstDefined(session, "csrfToken", "csrf_token") || "");
    return { user, csrfToken };
  }

  function extractCredentials(data, fallbackUsername = "") {
    const credentials = firstDefined(data, "credentials") || {};
    return {
      licenseKey: String(firstDefined(credentials, "licenseKey", "license_key") || firstDefined(data, "licenseKey", "license_key") || ""),
      adminUsername: String(firstDefined(credentials, "adminUsername", "admin_username", "username") || firstDefined(data, "adminUsername", "admin_username", "username") || fallbackUsername || ""),
      temporaryPassword: String(firstDefined(credentials, "temporaryPassword", "temporary_password", "password") || firstDefined(data, "temporaryPassword", "temporary_password", "password") || ""),
    };
  }

  function displayError(error) {
    if (error instanceof ApiError) return error.message;
    return "Terjadi kesalahan. Coba lagi.";
  }

  function makeElement(tag, { className = "", text = "", attrs = {}, dataset = {} } = {}, children = []) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== "") node.textContent = String(text);
    for (const [name, value] of Object.entries(attrs)) {
      if (value !== undefined && value !== null) node.setAttribute(name, String(value));
    }
    for (const [name, value] of Object.entries(dataset)) node.dataset[name] = String(value);
    for (const child of children) if (child) node.append(child);
    return node;
  }

  function setMessage(element, message = "", type = "") {
    element.textContent = message;
    element.className = `form-message${type ? ` ${type}` : ""}`;
  }

  function setButtonBusy(button, busy, busyLabel = "Memproses…") {
    if (!button) return;
    if (busy) {
      button.dataset.originalLabel = button.textContent;
      button.textContent = busyLabel;
      button.classList.add("btn-loading");
      button.disabled = true;
    } else {
      button.textContent = button.dataset.originalLabel || button.textContent;
      delete button.dataset.originalLabel;
      button.classList.remove("btn-loading");
      button.disabled = false;
    }
  }

  function setGlobalBusy(busy, label = "Memproses…") {
    $("#busyLabel").textContent = label;
    $("#globalBusy").hidden = !busy;
  }

  function toast(title, message = "", type = "") {
    const region = $("#toastRegion");
    const card = makeElement("div", { className: `toast${type ? ` ${type}` : ""}` });
    card.append(makeElement("strong", { text: title }));
    if (message) card.append(document.createTextNode(message));
    region.append(card);
    window.setTimeout(() => {
      card.classList.add("closing");
      window.setTimeout(() => card.remove(), 200);
    }, 5200);
  }

  function showDialog(dialog) {
    if (!dialog.open) dialog.showModal();
  }

  function closeDialog(dialog) {
    if (dialog?.open) dialog.close();
  }

  async function copyText(text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      const copied = document.execCommand("copy");
      textarea.remove();
      if (!copied) throw new Error("copy failed");
    }
    toast("Tersalin", "Simpan nilai ini di tempat aman.", "success");
  }

  function renderLoading(container, count = 3) {
    container.replaceChildren(...Array.from({ length: count }, () => makeElement("div", { className: "skeleton", attrs: { "aria-hidden": "true" } })));
  }

  function renderEmpty(container, title, copy) {
    const empty = makeElement("div", { className: "empty-state" }, [
      makeElement("strong", { text: title }),
      makeElement("p", { text: copy }),
    ]);
    container.replaceChildren(empty);
  }

  function statusBadge(status) {
    const safeStatus = STATUS_LABELS[status] ? status : "unknown";
    return makeElement("span", { className: `status-badge ${safeStatus}`, text: STATUS_LABELS[safeStatus] });
  }

  function adminStatus(admin) {
    const raw = String(firstDefined(admin, "status") || (firstDefined(admin, "disabledAt", "disabled_at") ? "disabled" : "active")).toLowerCase();
    return ["disabled", "inactive", "revoked"].includes(raw) ? "disabled" : "active";
  }

  function humanizeAction(action) {
    const key = String(action || "unknown");
    if (AUDIT_ACTION_LABELS[key]) return AUDIT_ACTION_LABELS[key];
    return key.replace(/[._-]+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
  }

  function showAuth(message = "") {
    state.csrfToken = "";
    state.user = null;
    $("#appView").hidden = true;
    $("#authView").hidden = false;
    $("#loginPassword").value = "";
    $("#loginTotp").value = "";
    setMessage($("#loginMessage"), message, message ? "error" : "");
    window.setTimeout(() => $("#loginUsername").focus(), 0);
  }

  function showApp(session) {
    state.user = session.user || {};
    state.csrfToken = session.csrfToken;
    const username = String(firstDefined(state.user, "username", "name", "displayName", "display_name") || "Super Admin");
    $("#currentUsername").textContent = username;
    $("#userAvatar").textContent = username.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "SA";
    $("#authView").hidden = true;
    $("#appView").hidden = false;
    navigate("dashboard", { force: true });
  }

  function expireSession() {
    if ($("#appView").hidden) return;
    showAuth("Sesi berakhir. Masuk kembali untuk melanjutkan.");
  }

  async function restoreSession() {
    try {
      const data = await API.session();
      const session = extractSession(data);
      if (!session.csrfToken) throw new ApiError("Token keamanan sesi tidak tersedia.", { code: "CSRF_TOKEN_MISSING" });
      showApp(session);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        showAuth();
        return;
      }
      showAuth(displayError(error));
    }
  }

  function navigate(view, { force = false } = {}) {
    if (!force && state.currentView === view) return;
    state.currentView = view;
    $$('[data-view-panel]').forEach((panel) => { panel.hidden = panel.dataset.viewPanel !== view; });
    $$('[data-view]').forEach((button) => button.classList.toggle("active", button.dataset.view === view));
    $("#mainContent").focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: "smooth" });

    if (view === "dashboard" && (!state.dashboardLoaded || force)) loadDashboard();
    if (view === "licenses" && (!state.licensesLoaded || force)) loadLicenses({ reset: true });
    if (view === "audit" && (!state.auditLoaded || force)) loadAudit({ reset: true });
  }

  function summaryValue(summary, keys, fallback) {
    for (const key of keys) {
      const value = firstDefined(summary, key);
      if (value !== undefined) return asNumber(value, fallback);
    }
    return fallback;
  }

  function deriveStats(items, summary, pagination) {
    const counts = { active: 0, expiring: 0, expired: 0, revoked: 0 };
    const uniqueSchools = new Set();
    for (const item of items) {
      const status = licenseStatus(item);
      if (counts[status] !== undefined) counts[status] += 1;
      const id = schoolId(item) || schoolCode(item);
      if (id) uniqueSchools.add(id);
    }
    const fallbackTotal = pagination?.total || uniqueSchools.size || items.length;
    const totalSchools = summaryValue(summary, ["totalSchools", "total_schools", "schools", "total"], fallbackTotal);
    const expiring = summaryValue(summary, ["expiring", "expiringSoon", "expiring_soon", "expiringLicenses", "expiring_licenses"], counts.expiring);
    const active = summaryValue(summary, ["active", "activeLicenses", "active_licenses"], counts.active + counts.expiring);
    const expired = summaryValue(summary, ["expired", "expiredLicenses", "expired_licenses"], counts.expired);
    const revoked = summaryValue(summary, ["revoked", "revokedLicenses", "revoked_licenses"], counts.revoked);
    return { totalSchools, active, expiring, expired, revoked };
  }

  async function loadDashboard({ silent = false } = {}) {
    const attention = $("#attentionList");
    if (!silent) {
      renderLoading(attention, 3);
      ["statSchools", "statActive", "statExpiring", "statExpired", "statRevoked"].forEach((id) => { $(`#${id}`).textContent = "—"; });
    }
    try {
      const data = await API.listLicenses({ limit: 100, offset: 0 });
      const result = normalizeLicenseList(data);
      state.dashboardItems = result.items;
      state.dashboardLoaded = true;
      const stats = deriveStats(result.items, result.summary, result.pagination);
      $("#statSchools").textContent = String(stats.totalSchools);
      $("#statActive").textContent = String(stats.active);
      $("#statExpiring").textContent = String(stats.expiring);
      $("#statExpired").textContent = String(stats.expired);
      $("#statRevoked").textContent = String(stats.revoked);
      renderAttention(result.items);
      renderHealth(stats);
    } catch (error) {
      renderEmpty(attention, "Dashboard gagal dimuat", displayError(error));
      if (!silent) toast("Gagal memuat dashboard", displayError(error), "error");
    }
  }

  function renderAttention(items) {
    const priority = { revoked: 0, expired: 1, expiring: 2, active: 3, unknown: 4 };
    const attentionItems = items
      .filter((item) => licenseStatus(item) !== "active")
      .sort((a, b) => {
        const statusDifference = priority[licenseStatus(a)] - priority[licenseStatus(b)];
        if (statusDifference) return statusDifference;
        return (parseDate(licenseExpiry(a))?.getTime() || Infinity) - (parseDate(licenseExpiry(b))?.getTime() || Infinity);
      })
      .slice(0, 6);

    if (!attentionItems.length) {
      renderEmpty($("#attentionList"), "Semua lisensi sehat", "Tidak ada lisensi kedaluwarsa, dicabut, atau segera berakhir.");
      return;
    }

    const rows = attentionItems.map((item) => {
      const main = makeElement("div", { className: "mini-row-main" }, [
        makeElement("strong", { text: schoolName(item) }),
        makeElement("small", { text: `${schoolCode(item)} · berakhir ${formatDate(licenseExpiry(item))}` }),
      ]);
      const action = makeElement("button", {
        className: "btn btn-secondary btn-small",
        text: "Detail",
        attrs: { type: "button", "aria-label": `Buka detail ${schoolName(item)}` },
        dataset: { licenseId: licenseId(item) },
      });
      return makeElement("div", { className: "mini-row" }, [main, action]);
    });
    $("#attentionList").replaceChildren(...rows);
  }

  function renderHealth(stats) {
    const denominator = Math.max(stats.totalSchools, 0);
    const percentage = denominator ? Math.max(0, Math.min(100, Math.round((stats.active / denominator) * 100))) : 0;
    $("#healthRing").style.setProperty("--health-angle", `${percentage * 3.6}deg`);
    $("#healthValue").textContent = `${percentage}%`;
    $("#healthCopy").textContent = denominator
      ? `${stats.active} dari ${denominator} lisensi aktif. ${stats.expiring} di antaranya perlu diperpanjang dalam 30 hari.`
      : "Belum ada sekolah berlisensi.";
  }

  function currentLicenseParams(offset = 0) {
    const q = $("#licenseSearch").value.trim();
    const filter = $("#licenseStatusFilter").value;
    if (filter === "expiring") return { q, status: "active", expiringWithinDays: 30, limit: 30, offset };
    return { q, status: filter === "all" ? "" : filter, limit: 30, offset };
  }

  async function loadLicenses({ reset = false, silent = false } = {}) {
    const requestId = ++state.licenseRequestId;
    const offset = reset ? 0 : state.licenseItems.length;
    if (reset && !silent) renderLoading($("#licenseList"), 6);
    $("#loadMoreLicenses").disabled = true;

    try {
      const data = await API.listLicenses(currentLicenseParams(offset));
      if (requestId !== state.licenseRequestId) return;
      const result = normalizeLicenseList(data);
      state.licenseItems = reset ? result.items : state.licenseItems.concat(result.items);
      state.licensePagination = result.pagination;
      state.licensesLoaded = true;
      renderLicenses();
      $("#licenseUpdatedAt").textContent = `Diperbarui ${new Intl.DateTimeFormat("id-ID", { hour: "2-digit", minute: "2-digit" }).format(new Date())}`;
    } catch (error) {
      if (requestId !== state.licenseRequestId) return;
      if (reset) renderEmpty($("#licenseList"), "Lisensi gagal dimuat", displayError(error));
      toast("Gagal memuat lisensi", displayError(error), "error");
    } finally {
      if (requestId === state.licenseRequestId) $("#loadMoreLicenses").disabled = false;
    }
  }

  function renderLicenses() {
    const container = $("#licenseList");
    if (!state.licenseItems.length) {
      renderEmpty(container, "Tidak ada hasil", "Ubah pencarian atau filter, atau buat lisensi sekolah baru.");
    } else {
      container.replaceChildren(...state.licenseItems.map(createLicenseCard));
    }
    const total = state.licensePagination.total;
    $("#licenseResultCount").textContent = total > state.licenseItems.length
      ? `${state.licenseItems.length} dari ${total} lisensi`
      : `${state.licenseItems.length} lisensi`;
    $("#licenseLoadMore").hidden = !state.licensePagination.hasMore;
  }

  function createLicenseCard(bundle) {
    const status = licenseStatus(bundle);
    const heading = makeElement("div", {}, [
      makeElement("span", { className: "school-code", text: schoolCode(bundle) }),
      makeElement("h3", { text: schoolName(bundle) }),
    ]);
    const top = makeElement("div", { className: "license-card-top" }, [heading, statusBadge(status)]);
    const meta = makeElement("div", { className: "license-meta-grid" }, [
      makeElement("div", {}, [makeElement("span", { text: "Berakhir" }), makeElement("strong", { text: formatDate(licenseExpiry(bundle)) })]),
      makeElement("div", {}, [makeElement("span", { text: "Admin" }), makeElement("strong", { text: `${bundle.adminCount}/${licenseMaxAdmins(bundle) || "—"}` })]),
    ]);
    return makeElement("button", {
      className: "license-card",
      attrs: { type: "button", "aria-label": `Buka detail lisensi ${schoolName(bundle)}` },
      dataset: { licenseId: licenseId(bundle) },
    }, [top, meta]);
  }

  async function openLicenseDetail(id, { preserveDialog = false } = {}) {
    if (!id) return;
    state.selectedLicenseId = String(id);
    if (!preserveDialog) {
      $("#detailBody").replaceChildren(...Array.from({ length: 3 }, () => makeElement("div", { className: "skeleton" })));
      showDialog($("#detailDialog"));
    }
    try {
      const data = await API.getLicense(id);
      if (state.selectedLicenseId !== String(id)) return;
      const detail = normalizeDetail(data);
      state.selectedDetail = detail;
      renderDetail(detail);
    } catch (error) {
      if (state.selectedLicenseId !== String(id)) return;
      renderEmpty($("#detailBody"), "Detail gagal dimuat", displayError(error));
      toast("Gagal memuat detail", displayError(error), "error");
    }
  }

  function detailItem(label, value) {
    return makeElement("div", { className: "detail-item" }, [
      makeElement("span", { text: label }),
      makeElement("strong", { text: value || "—" }),
    ]);
  }

  function renderDetail(detail) {
    const { bundle, admins, licenseAudit } = detail;
    const status = licenseStatus(bundle);
    const body = $("#detailBody");
    const heroCopy = makeElement("div", {}, [
      makeElement("span", { className: "school-code", text: schoolCode(bundle) }),
      makeElement("h3", { text: schoolName(bundle) }),
    ]);
    const hero = makeElement("div", { className: "detail-hero" }, [heroCopy, statusBadge(status)]);
    const school = bundle.school;
    const grid = makeElement("div", { className: "detail-grid" }, [
      detailItem("Jenjang", String(firstDefined(school, "level", "schoolLevel", "school_level") || "—")),
      detailItem("Kepala sekolah", String(firstDefined(school, "principalName", "principal_name") || "—")),
      detailItem("Mulai berlaku", formatDate(licenseStart(bundle))),
      detailItem("Berakhir", formatDate(licenseExpiry(bundle))),
      detailItem("Kuota admin", String(licenseMaxAdmins(bundle) || "—")),
      detailItem("Admin terdaftar", String(admins.length)),
      detailItem("ID lisensi", licenseId(bundle)),
      detailItem("ID sekolah", schoolId(bundle)),
    ]);

    const actions = makeElement("div", { className: "detail-actions" });
    actions.append(makeElement("button", { className: "btn btn-secondary btn-small", text: "Perpanjang", attrs: { type: "button" }, dataset: { detailAction: "extend" } }));
    if (status === "revoked") {
      actions.append(makeElement("button", { className: "btn btn-success btn-small", text: "Aktifkan kembali", attrs: { type: "button" }, dataset: { detailAction: "reactivate" } }));
    } else {
      actions.append(makeElement("button", { className: "btn btn-danger btn-small", text: "Cabut lisensi", attrs: { type: "button" }, dataset: { detailAction: "revoke" } }));
    }
    const maxAdmins = licenseMaxAdmins(bundle);
    const addDisabled = maxAdmins > 0 && admins.filter((admin) => adminStatus(admin) === "active").length >= maxAdmins;
    const addButton = makeElement("button", { className: "btn btn-primary btn-small", text: "Tambah admin", attrs: { type: "button" }, dataset: { detailAction: "add-admin" } });
    addButton.disabled = addDisabled;
    if (addDisabled) addButton.title = "Kuota admin aktif sudah penuh";
    actions.append(addButton);

    const adminTitle = makeElement("h3", { className: "section-title", text: "Akun admin sekolah" });
    const adminList = makeElement("div", { className: "admin-list" });
    if (!admins.length) {
      renderEmpty(adminList, "Belum ada admin", "Tambahkan akun admin untuk sekolah ini.");
    } else {
      adminList.replaceChildren(...admins.map(createAdminRow));
    }

    const nodes = [hero, grid, actions, adminTitle, adminList];
    if (licenseAudit.length) {
      nodes.push(makeElement("h3", { className: "section-title", text: "Audit lisensi terbaru", attrs: { style: "margin-top:24px" } }));
      const auditList = makeElement("div", { className: "audit-list" });
      auditList.replaceChildren(...licenseAudit.slice(0, 8).map(createAuditCard));
      nodes.push(auditList);
    }
    body.replaceChildren(...nodes);
  }

  function createAdminRow(admin) {
    const id = String(firstDefined(admin, "id", "adminId", "admin_id") || "");
    const username = String(firstDefined(admin, "username") || "Admin tanpa username");
    const displayName = String(firstDefined(admin, "displayName", "display_name") || "");
    const status = adminStatus(admin);
    const copy = makeElement("div", { className: "admin-copy" }, [
      makeElement("strong", { text: username }),
      makeElement("small", { text: `${displayName ? `${displayName} · ` : ""}${STATUS_LABELS[status]}` }),
    ]);
    const actions = makeElement("div", { className: "admin-actions" });
    const reset = makeElement("button", {
      className: "btn btn-secondary btn-small",
      text: "Reset password",
      attrs: { type: "button" },
      dataset: { adminAction: "reset", adminId: id, adminUsername: username },
    });
    actions.append(reset);
    if (status !== "disabled") {
      actions.append(makeElement("button", {
        className: "btn btn-danger btn-small",
        text: "Nonaktifkan",
        attrs: { type: "button" },
        dataset: { adminAction: "disable", adminId: id, adminUsername: username },
      }));
    }
    return makeElement("div", { className: "admin-row" }, [copy, actions]);
  }

  function openCreateDialog() {
    const form = $("#createForm");
    form.reset();
    $("#duration30").checked = true;
    $("#maxAdmins").value = "1";
    $("#customDateField").hidden = true;
    $("#customExpiresAt").required = false;
    setMessage($("#createMessage"));
    showDialog($("#createDialog"));
    window.setTimeout(() => $("#schoolName").focus(), 0);
  }

  function getCreatePayload() {
    const schoolNameValue = $("#schoolName").value.trim();
    const schoolCodeValue = $("#schoolCode").value.trim().toUpperCase();
    const level = $("#schoolLevel").value;
    const principalName = $("#principalName").value.trim();
    const maxAdmins = Number($("#maxAdmins").value);
    const adminUsername = $("#initialAdminUsername").value.trim();
    const duration = $('input[name="duration"]:checked', $("#createForm"))?.value || "30";

    if (!schoolNameValue) throw new ApiError("Nama sekolah wajib diisi.");
    if (!/^[A-Z0-9_-]{2,32}$/.test(schoolCodeValue)) throw new ApiError("Kode sekolah harus 2–32 karakter: huruf, angka, tanda hubung, atau garis bawah.");
    if (!level) throw new ApiError("Pilih jenjang sekolah.");
    if (!principalName) throw new ApiError("Nama kepala sekolah wajib diisi.");
    if (!Number.isInteger(maxAdmins) || maxAdmins < 1 || maxAdmins > 100) throw new ApiError("Maksimum admin harus 1–100.");
    if (!/^[A-Za-z0-9._-]{3,80}$/.test(adminUsername)) throw new ApiError("Username admin harus 3–80 karakter dan hanya memakai huruf, angka, titik, garis bawah, atau tanda hubung.");

    const payload = { schoolCode: schoolCodeValue, schoolName: schoolNameValue, level, principalName, maxAdmins, adminUsername };
    if (duration === "custom") {
      const expiresAt = $("#customExpiresAt").value;
      if (!expiresAt || expiresAt < tomorrowInputValue()) throw new ApiError("Tanggal berakhir custom harus setelah hari ini.");
      payload.expiresAt = expiresAt;
    } else {
      payload.durationDays = Number(duration);
    }
    return payload;
  }

  async function submitCreate(event) {
    event.preventDefault();
    const button = $("#createSubmit");
    setMessage($("#createMessage"));
    let payload;
    try {
      payload = getCreatePayload();
    } catch (error) {
      setMessage($("#createMessage"), displayError(error), "error");
      return;
    }

    setButtonBusy(button, true, "Membuat…");
    try {
      const data = await API.createLicense(payload);
      const credentials = extractCredentials(data, payload.adminUsername);
      closeDialog($("#createDialog"));
      showCredentials("Lisensi berhasil dibuat", credentials, `${payload.schoolName} · ${payload.schoolCode}`);
      toast("Lisensi dibuat", `${payload.schoolName} kini terdaftar.`, "success");
      await refreshDataAfterMutation();
    } catch (error) {
      setMessage($("#createMessage"), displayError(error), "error");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function showCredentials(title, credentials, subtitle = "Nilai ini tidak dapat ditampilkan kembali.") {
    const secrets = [
      ["License key", credentials.licenseKey],
      ["Username admin", credentials.adminUsername],
      ["Password sementara", credentials.temporaryPassword],
    ].filter(([, value]) => value);

    $("#credentialsTitle").textContent = title;
    $("#credentialsSubtitle").textContent = subtitle;
    $("#credentialsAcknowledged").checked = false;
    $("#closeCredentials").disabled = true;
    const container = $("#credentialSecrets");
    container.replaceChildren(...secrets.map(([label, value], index) => {
      const valueId = `credentialValue${index}`;
      const code = makeElement("code", { className: "secret-value", text: value, attrs: { id: valueId } });
      const copy = makeElement("button", { className: "btn btn-secondary btn-small", text: "Salin", attrs: { type: "button" }, dataset: { copyTarget: valueId } });
      return makeElement("div", { className: "secret-item" }, [
        makeElement("label", { text: label, attrs: { for: valueId } }),
        makeElement("div", { className: "secret-value-row" }, [code, copy]),
      ]);
    }));

    if (!secrets.length) {
      renderEmpty(container, "Kredensial tidak tersedia", "Server tidak mengembalikan nilai sekali tampil. Periksa audit sebelum mengulang operasi.");
    }
    showDialog($("#credentialsDialog"));
  }

  function clearCredentialsDialog() {
    $("#credentialSecrets").replaceChildren();
    $("#credentialsTitle").textContent = "Simpan kredensial sekarang";
    $("#credentialsSubtitle").textContent = "Nilai ini tidak dapat ditampilkan kembali.";
    $("#credentialsAcknowledged").checked = false;
    $("#closeCredentials").disabled = true;
  }

  function openExtendDialog(mode = "extend") {
    const bundle = state.selectedDetail?.bundle;
    if (!bundle) return;
    $("#extendDialog").dataset.mode = mode;
    $("#extendTitle").textContent = mode === "reactivate" ? "Aktifkan kembali lisensi" : "Perpanjang lisensi";
    $("#extendDays").value = "30";
    $("#extendCustomField").hidden = true;
    $("#extendCustomDate").required = false;
    $("#extendCustomDate").min = tomorrowInputValue();
    $("#extendCustomDate").value = tomorrowInputValue();
    setMessage($("#extendMessage"));
    showDialog($("#extendDialog"));
  }

  async function submitExtend(event) {
    event.preventDefault();
    const id = state.selectedLicenseId;
    if (!id) return;
    const mode = $("#extendDialog").dataset.mode || "extend";
    const selection = $("#extendDays").value;
    const payload = {};
    if (selection === "custom") {
      const expiresAt = $("#extendCustomDate").value;
      if (!expiresAt || expiresAt < tomorrowInputValue()) {
        setMessage($("#extendMessage"), "Tanggal berakhir baru harus setelah hari ini.", "error");
        return;
      }
      payload.expiresAt = expiresAt;
    } else {
      payload.days = Number(selection);
    }

    const button = $("#extendSubmit");
    setButtonBusy(button, true, mode === "reactivate" ? "Mengaktifkan…" : "Memperpanjang…");
    setMessage($("#extendMessage"));
    try {
      if (mode === "reactivate") await API.reactivateLicense(id, payload);
      else await API.extendLicense(id, payload);
      closeDialog($("#extendDialog"));
      toast(mode === "reactivate" ? "Lisensi aktif kembali" : "Lisensi diperpanjang", "Status terbaru sudah diterapkan.", "success");
      await refreshDataAfterMutation({ detailId: id });
    } catch (error) {
      setMessage($("#extendMessage"), displayError(error), "error");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function openAdminDialog() {
    $("#adminForm").reset();
    setMessage($("#adminMessage"));
    showDialog($("#adminDialog"));
    window.setTimeout(() => $("#newAdminUsername").focus(), 0);
  }

  async function submitAdmin(event) {
    event.preventDefault();
    const id = state.selectedLicenseId;
    const username = $("#newAdminUsername").value.trim();
    if (!/^[A-Za-z0-9._-]{3,80}$/.test(username)) {
      setMessage($("#adminMessage"), "Username harus 3–80 karakter dan hanya memakai huruf, angka, titik, garis bawah, atau tanda hubung.", "error");
      return;
    }
    const button = $("#adminSubmit");
    setButtonBusy(button, true, "Menambahkan…");
    setMessage($("#adminMessage"));
    try {
      const data = await API.addAdmin(id, { username });
      const credentials = extractCredentials(data, username);
      closeDialog($("#adminDialog"));
      showCredentials("Admin sekolah ditambahkan", credentials, `${schoolName(state.selectedDetail.bundle)} · simpan password sementara sekarang`);
      toast("Admin ditambahkan", username, "success");
      await refreshDataAfterMutation({ detailId: id });
    } catch (error) {
      setMessage($("#adminMessage"), displayError(error), "error");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function openConfirm({ title, subtitle = "", copy, actionLabel, danger = true, reasonVisible = false, reasonRequired = false, run }) {
    state.confirmAction = { run, reasonRequired };
    $("#confirmTitle").textContent = title;
    $("#confirmSubtitle").textContent = subtitle;
    $("#confirmCopy").textContent = copy;
    $("#confirmReasonField").hidden = !reasonVisible;
    $("#confirmReason").required = reasonRequired;
    $("#confirmReason").value = "";
    setMessage($("#confirmMessage"));
    const button = $("#confirmAction");
    button.textContent = actionLabel;
    button.className = `btn ${danger ? "btn-danger" : "btn-success"}`;
    showDialog($("#confirmDialog"));
  }

  async function executeConfirm() {
    const pending = state.confirmAction;
    if (!pending) return;
    const reason = $("#confirmReason").value.trim();
    if (pending.reasonRequired && !reason) {
      setMessage($("#confirmMessage"), "Alasan wajib diisi untuk jejak audit.", "error");
      $("#confirmReason").focus();
      return;
    }
    const button = $("#confirmAction");
    setButtonBusy(button, true);
    setMessage($("#confirmMessage"));
    try {
      await pending.run(reason);
      closeDialog($("#confirmDialog"));
      state.confirmAction = null;
    } catch (error) {
      setMessage($("#confirmMessage"), displayError(error), "error");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function handleDetailAction(action) {
    const detail = state.selectedDetail;
    if (!detail) return;
    const id = state.selectedLicenseId;
    if (action === "extend") {
      openExtendDialog("extend");
      return;
    }
    if (action === "add-admin") {
      openAdminDialog();
      return;
    }
    if (action === "revoke") {
      openConfirm({
        title: "Cabut lisensi sekolah?",
        subtitle: schoolName(detail.bundle),
        copy: "Akses admin sekolah akan diblokir pada pemeriksaan lisensi berikutnya. Tindakan ini dapat dibalik dengan aktivasi ulang.",
        actionLabel: "Cabut lisensi",
        reasonVisible: true,
        reasonRequired: true,
        run: async (reason) => {
          await API.revokeLicense(id, { reason });
          toast("Lisensi dicabut", schoolName(detail.bundle), "success");
          await refreshDataAfterMutation({ detailId: id });
        },
      });
      return;
    }
    if (action === "reactivate") {
      if (licenseStatus(detail.bundle) === "revoked" && (daysUntil(licenseExpiry(detail.bundle)) ?? 1) < 0) {
        openExtendDialog("reactivate");
        return;
      }
      openConfirm({
        title: "Aktifkan kembali lisensi?",
        subtitle: schoolName(detail.bundle),
        copy: "Admin sekolah akan kembali memperoleh akses selama tanggal lisensi masih berlaku.",
        actionLabel: "Aktifkan kembali",
        danger: false,
        reasonVisible: true,
        run: async (reason) => {
          const payload = reason ? { reason } : {};
          await API.reactivateLicense(id, payload);
          toast("Lisensi aktif kembali", schoolName(detail.bundle), "success");
          await refreshDataAfterMutation({ detailId: id });
        },
      });
    }
  }

  function handleAdminAction(button) {
    const action = button.dataset.adminAction;
    const adminId = button.dataset.adminId;
    const username = button.dataset.adminUsername || "admin";
    if (!adminId) return;
    if (action === "reset") {
      openConfirm({
        title: "Reset password admin?",
        subtitle: username,
        copy: "Password lama langsung tidak berlaku. Password sementara baru hanya ditampilkan sekali.",
        actionLabel: "Reset password",
        reasonVisible: true,
        run: async (reason) => {
          const data = await API.resetAdminPassword(adminId, reason ? { reason } : {});
          const credentials = extractCredentials(data, username);
          showCredentials("Password admin direset", credentials, `${username} · simpan password sementara sekarang`);
          toast("Password direset", username, "success");
          await refreshDataAfterMutation({ detailId: state.selectedLicenseId });
        },
      });
      return;
    }
    if (action === "disable") {
      openConfirm({
        title: "Nonaktifkan admin sekolah?",
        subtitle: username,
        copy: "Akun ini tidak dapat login lagi. Akun lain pada sekolah tidak terpengaruh.",
        actionLabel: "Nonaktifkan",
        reasonVisible: true,
        reasonRequired: true,
        run: async (reason) => {
          await API.disableAdmin(adminId, { reason });
          toast("Admin dinonaktifkan", username, "success");
          await refreshDataAfterMutation({ detailId: state.selectedLicenseId });
        },
      });
    }
  }

  async function refreshDataAfterMutation({ detailId = "" } = {}) {
    const jobs = [loadDashboard({ silent: true })];
    if (state.licensesLoaded) jobs.push(loadLicenses({ reset: true, silent: true }));
    if (state.auditLoaded) jobs.push(loadAudit({ reset: true, silent: true }));
    await Promise.allSettled(jobs);
    if (detailId && $("#detailDialog").open) await openLicenseDetail(detailId, { preserveDialog: true });
  }

  function auditAction(item) {
    return String(firstDefined(item, "action", "event", "type") || "unknown");
  }

  function auditActor(item) {
    const actor = firstDefined(item, "actor");
    if (actor && typeof actor === "object") return String(firstDefined(actor, "username", "name", "id") || "Sistem");
    return String(firstDefined(item, "actorUsername", "actor_username", "username", "actorId", "actor_id") || actor || "Sistem");
  }

  function auditSchool(item) {
    const school = firstDefined(item, "school");
    if (school && typeof school === "object") return String(firstDefined(school, "name", "schoolName", "code", "schoolCode") || "");
    return String(firstDefined(item, "schoolName", "school_name", "schoolCode", "school_code", "schoolId", "school_id") || "");
  }

  function auditTime(item) {
    return firstDefined(item, "createdAt", "created_at", "timestamp", "occurredAt", "occurred_at");
  }

  function auditDescription(item) {
    return String(firstDefined(item, "description", "message", "reason") || "Perubahan tercatat oleh platform.");
  }

  function auditDetailPayload(item) {
    const result = {};
    for (const key of ["before", "after", "details", "metadata", "changes", "ipAddress", "ip_address", "userAgent", "user_agent"]) {
      const value = firstDefined(item, key);
      if (value !== undefined && value !== null && value !== "") result[key] = value;
    }
    return result;
  }

  function createAuditCard(item) {
    const action = auditAction(item);
    const top = makeElement("div", { className: "audit-top" }, [
      makeElement("span", { className: "audit-action", text: humanizeAction(action) }),
      makeElement("time", { className: "audit-time", text: formatDate(auditTime(item), true) }),
    ]);
    const copy = makeElement("p", { className: "audit-copy", text: auditDescription(item) });
    const meta = makeElement("div", { className: "audit-meta" }, [
      makeElement("span", { text: `Aktor: ${auditActor(item)}` }),
      auditSchool(item) ? makeElement("span", { text: `Sekolah: ${auditSchool(item)}` }) : null,
    ]);
    const card = makeElement("article", { className: "audit-card" }, [top, copy, meta]);
    const payload = auditDetailPayload(item);
    if (Object.keys(payload).length) {
      let detailText;
      try {
        detailText = JSON.stringify(payload, null, 2);
      } catch {
        detailText = "Detail tidak dapat ditampilkan.";
      }
      const details = makeElement("details", { className: "audit-details" }, [
        makeElement("summary", { text: "Lihat detail perubahan" }),
        makeElement("pre", { text: detailText }),
      ]);
      card.append(details);
    }
    return card;
  }

  function currentAuditParams(offset = 0) {
    const action = $("#auditActionFilter").value;
    return { action: action === "all" ? "" : action, limit: 30, offset };
  }

  async function loadAudit({ reset = false, silent = false } = {}) {
    const requestId = ++state.auditRequestId;
    const offset = reset ? 0 : state.auditItems.length;
    if (reset && !silent) renderLoading($("#auditList"), 5);
    $("#loadMoreAudit").disabled = true;
    try {
      const data = await API.audit(currentAuditParams(offset));
      if (requestId !== state.auditRequestId) return;
      const result = normalizeAuditResponse(data);
      state.auditItems = reset ? result.items : state.auditItems.concat(result.items);
      state.auditPagination = result.pagination;
      for (const item of result.items) state.auditActions.add(auditAction(item));
      state.auditLoaded = true;
      renderAuditActionOptions();
      renderAudit();
      $("#auditUpdatedAt").textContent = `Diperbarui ${new Intl.DateTimeFormat("id-ID", { hour: "2-digit", minute: "2-digit" }).format(new Date())}`;
    } catch (error) {
      if (requestId !== state.auditRequestId) return;
      if (reset) renderEmpty($("#auditList"), "Audit gagal dimuat", displayError(error));
      toast("Gagal memuat audit", displayError(error), "error");
    } finally {
      if (requestId === state.auditRequestId) $("#loadMoreAudit").disabled = false;
    }
  }

  function renderAuditActionOptions() {
    const select = $("#auditActionFilter");
    const selected = select.value || "all";
    const options = [makeElement("option", { text: "Semua aksi", attrs: { value: "all" } })];
    const actions = Array.from(state.auditActions).filter(Boolean).sort((a, b) => humanizeAction(a).localeCompare(humanizeAction(b), "id"));
    for (const action of actions) options.push(makeElement("option", { text: humanizeAction(action), attrs: { value: action } }));
    select.replaceChildren(...options);
    select.value = actions.includes(selected) || selected === "all" ? selected : "all";
  }

  function renderAudit() {
    const query = $("#auditSearch").value.trim().toLocaleLowerCase("id");
    const filtered = state.auditItems.filter((item) => {
      if (!query) return true;
      const haystack = [auditAction(item), humanizeAction(auditAction(item)), auditActor(item), auditSchool(item), auditDescription(item)].join(" ").toLocaleLowerCase("id");
      return haystack.includes(query);
    });
    const container = $("#auditList");
    if (!filtered.length) renderEmpty(container, "Tidak ada aktivitas", query ? "Tidak ada audit yang cocok dengan pencarian." : "Belum ada audit pada filter ini.");
    else container.replaceChildren(...filtered.map(createAuditCard));
    const total = state.auditPagination.total;
    $("#auditResultCount").textContent = query
      ? `${filtered.length} cocok dari ${state.auditItems.length} dimuat`
      : (total > state.auditItems.length ? `${state.auditItems.length} dari ${total} aktivitas` : `${state.auditItems.length} aktivitas`);
    $("#auditLoadMore").hidden = !state.auditPagination.hasMore;
  }

  async function logout() {
    const button = $("#logoutButton");
    setButtonBusy(button, true, "Keluar…");
    try {
      await API.logout();
      state.dashboardLoaded = false;
      state.licensesLoaded = false;
      state.auditLoaded = false;
      state.dashboardItems = [];
      state.licenseItems = [];
      state.auditItems = [];
      state.auditActions.clear();
      showAuth();
    } catch (error) {
      toast("Logout gagal", `${displayError(error)} Sesi tetap dipertahankan.`, "error");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function bindEvents() {
    $("#loginForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const username = $("#loginUsername").value.trim();
      const password = $("#loginPassword").value;
      const totp = $("#loginTotp").value.replace(/\D/g, "");
      if (!username || !password) {
        setMessage($("#loginMessage"), "Username dan password wajib diisi.", "error");
        return;
      }
      if (!/^\d{6}$/.test(totp)) {
        setMessage($("#loginMessage"), "Kode autentikator harus enam digit.", "error");
        return;
      }
      const button = $("#loginSubmit");
      setButtonBusy(button, true, "Memverifikasi…");
      setMessage($("#loginMessage"));
      try {
        const loginData = await API.login({ username, password, totp });
        const initialSession = extractSession(loginData);
        if (initialSession.csrfToken) state.csrfToken = initialSession.csrfToken;
        const sessionData = await API.session();
        const session = extractSession(sessionData);
        if (!session.csrfToken) throw new ApiError("Token keamanan sesi tidak tersedia.", { code: "CSRF_TOKEN_MISSING" });
        showApp(session);
      } catch (error) {
        $("#loginPassword").value = "";
        $("#loginTotp").value = "";
        setMessage($("#loginMessage"), displayError(error), "error");
        $("#loginPassword").focus();
      } finally {
        setButtonBusy(button, false);
      }
    });

    $("#loginTotp").addEventListener("input", (event) => { event.target.value = event.target.value.replace(/\D/g, "").slice(0, 6); });
    $("#schoolCode").addEventListener("input", (event) => { event.target.value = event.target.value.toUpperCase().replace(/[^A-Z0-9_-]/g, ""); });

    document.addEventListener("click", (event) => {
      const passwordToggle = event.target.closest("[data-password-toggle]");
      if (passwordToggle) {
        const input = document.getElementById(passwordToggle.dataset.passwordToggle);
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        passwordToggle.textContent = reveal ? "Tutup" : "Lihat";
        passwordToggle.setAttribute("aria-label", reveal ? "Sembunyikan password" : "Tampilkan password");
        return;
      }

      const copyButton = event.target.closest("[data-copy-target]");
      if (copyButton) {
        const target = document.getElementById(copyButton.dataset.copyTarget);
        if (target) copyText(target.textContent || "");
        return;
      }

      const closeButton = event.target.closest("[data-close-dialog]");
      if (closeButton) {
        closeDialog(document.getElementById(closeButton.dataset.closeDialog));
        return;
      }

      const navButton = event.target.closest("[data-view]");
      if (navButton) {
        navigate(navButton.dataset.view);
        return;
      }

      const viewLink = event.target.closest("[data-view-link]");
      if (viewLink) {
        navigate(viewLink.dataset.viewLink);
        return;
      }

      if (event.target.closest("[data-open-create]")) {
        openCreateDialog();
        return;
      }

      const refresh = event.target.closest("[data-refresh]");
      if (refresh) {
        const view = refresh.dataset.refresh;
        if (view === "dashboard") loadDashboard();
        if (view === "licenses") loadLicenses({ reset: true });
        if (view === "audit") loadAudit({ reset: true });
        return;
      }

      const licenseButton = event.target.closest("[data-license-id]");
      if (licenseButton) {
        openLicenseDetail(licenseButton.dataset.licenseId);
        return;
      }

      const detailAction = event.target.closest("[data-detail-action]");
      if (detailAction) {
        handleDetailAction(detailAction.dataset.detailAction);
        return;
      }

      const adminAction = event.target.closest("[data-admin-action]");
      if (adminAction) handleAdminAction(adminAction);
    });

    $("#logoutButton").addEventListener("click", logout);
    $("#createForm").addEventListener("submit", submitCreate);
    $("#extendForm").addEventListener("submit", submitExtend);
    $("#adminForm").addEventListener("submit", submitAdmin);
    $("#confirmAction").addEventListener("click", executeConfirm);

    $$('input[name="duration"]', $("#createForm")).forEach((input) => input.addEventListener("change", () => {
      const custom = $("#durationCustom").checked;
      $("#customDateField").hidden = !custom;
      $("#customExpiresAt").required = custom;
      if (custom && !$("#customExpiresAt").value) $("#customExpiresAt").value = tomorrowInputValue();
    }));

    $("#extendDays").addEventListener("change", () => {
      const custom = $("#extendDays").value === "custom";
      $("#extendCustomField").hidden = !custom;
      $("#extendCustomDate").required = custom;
    });

    $("#licenseSearch").addEventListener("input", () => {
      window.clearTimeout(state.filterTimer);
      state.filterTimer = window.setTimeout(() => loadLicenses({ reset: true }), 320);
    });
    $("#licenseStatusFilter").addEventListener("change", () => loadLicenses({ reset: true }));
    $("#clearFilters").addEventListener("click", () => {
      $("#licenseSearch").value = "";
      $("#licenseStatusFilter").value = "all";
      loadLicenses({ reset: true });
    });
    $("#loadMoreLicenses").addEventListener("click", () => loadLicenses());

    $("#auditSearch").addEventListener("input", () => {
      window.clearTimeout(state.auditSearchTimer);
      state.auditSearchTimer = window.setTimeout(renderAudit, 180);
    });
    $("#auditActionFilter").addEventListener("change", () => loadAudit({ reset: true }));
    $("#clearAuditFilters").addEventListener("click", () => {
      $("#auditSearch").value = "";
      $("#auditActionFilter").value = "all";
      loadAudit({ reset: true });
    });
    $("#loadMoreAudit").addEventListener("click", () => loadAudit());

    $("#credentialsAcknowledged").addEventListener("change", (event) => { $("#closeCredentials").disabled = !event.target.checked; });
    $("#closeCredentials").addEventListener("click", () => closeDialog($("#credentialsDialog")));
    $("#credentialsDialog").addEventListener("cancel", (event) => {
      if (!$("#credentialsAcknowledged").checked) event.preventDefault();
    });
    $("#credentialsDialog").addEventListener("close", clearCredentialsDialog);
    $("#detailDialog").addEventListener("close", () => {
      state.selectedLicenseId = "";
      state.selectedDetail = null;
      $("#detailBody").replaceChildren();
    });
    $("#confirmDialog").addEventListener("close", () => {
      state.confirmAction = null;
      setMessage($("#confirmMessage"));
    });
  }

  function initialize() {
    const minimumDate = tomorrowInputValue();
    $("#customExpiresAt").min = minimumDate;
    $("#extendCustomDate").min = minimumDate;
    bindEvents();
    restoreSession();
  }

  initialize();
})();
