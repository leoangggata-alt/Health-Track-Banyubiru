// admin/_worker.js
// Cloudflare Pages Advanced Worker for School Admin: Serves static assets and proxies /api/* to Platform API

const SECURITY_HEADERS = {
  "content-security-policy":
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; upgrade-insecure-requests",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "cross-origin-opener-policy": "same-origin",
};

const DEFAULT_API_URL = "https://vitaqu-platform-api.abel-lab-security-2026.workers.dev";

function withSecurityHeaders(response) {
  const secured = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    secured.headers.set(name, value);
  }
  return secured;
}

function jsonError(message, status = 500) {
  return withSecurityHeaders(
    new Response(JSON.stringify({ ok: false, error: { code: "PROXY_ERROR", message } }), {
      status,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    })
  );
}

async function proxyApi(request, env) {
  const targetBase = env.PLATFORM_API_URL || DEFAULT_API_URL;
  let upstreamBase;
  try {
    upstreamBase = new URL(targetBase);
  } catch {
    return jsonError("PLATFORM_API_URL tidak valid.");
  }

  const incoming = new URL(request.url);
  const upstream = new URL(incoming.pathname + incoming.search, upstreamBase);
  const headers = new Headers(request.headers);
  headers.set("x-vitaqu-portal", "admin");
  if (env.PLATFORM_PROXY_SECRET) {
    headers.set("x-vitaqu-proxy-secret", env.PLATFORM_PROXY_SECRET);
  }
  headers.set("x-forwarded-host", incoming.host);
  headers.set("x-forwarded-proto", incoming.protocol.slice(0, -1));

  const init = { method: request.method, headers, redirect: "manual" };
  if (!/^(GET|HEAD)$/.test(request.method)) {
    init.body = request.body;
  }

  let response;
  try {
    response = await fetch(upstream, init);
  } catch {
    return jsonError("Platform API tidak dapat dihubungi.", 502);
  }

  const proxied = new Response(response.body, response);
  proxied.headers.set("cache-control", "no-store");
  return withSecurityHeaders(proxied);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      return proxyApi(request, env);
    }
    if (!env.ASSETS) {
      return jsonError("Binding ASSETS belum tersedia.");
    }
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  },
};
