// platform-api/src/index.ts
// Main Cloudflare Worker entry point for VITAQU Central Licensing & School Admin Platform

import { Env } from "./auth.ts";
import { handleSuperRoute } from "./routes/super.ts";
import { handleAdminRoute } from "./routes/admin.ts";
import { handleMemberRoute } from "./routes/member.ts";

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("origin") || "";
    const clientIp = request.headers.get("cf-connecting-ip") || "127.0.0.1";

    // Handle CORS preflight
    if (request.method.toUpperCase() === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin || "*",
          "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers":
            "Content-Type, Accept, X-CSRF-Token, x-csrf-token, x-vitaqu-portal, x-vitaqu-proxy-secret",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Max-Age": "86400",
          ...SECURITY_HEADERS,
        },
      });
    }

    // Healthcheck endpoint
    if (url.pathname === "/api/health" || url.pathname === "/") {
      return new Response(
        JSON.stringify({
          ok: true,
          service: "vitaqu-platform-api",
          version: "2026.11",
          time: new Date().toISOString(),
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": origin || "*",
            "Access-Control-Allow-Credentials": "true",
            ...SECURITY_HEADERS,
          },
        }
      );
    }

    // Routing
    try {
      let response: Response;
      if (url.pathname.startsWith("/api/super/") || url.pathname === "/api/super") {
        response = await handleSuperRoute(request, url, env.DB, clientIp);
      } else if (url.pathname.startsWith("/api/admin/") || url.pathname === "/api/admin") {
        response = await handleAdminRoute(request, url, env.DB, clientIp);
      } else if (url.pathname.startsWith("/api/member/") || url.pathname === "/api/member") {
        response = await handleMemberRoute(request, url, env.DB, clientIp);
      } else {
        response = new Response(
          JSON.stringify({ ok: false, error: { message: "Rute API tidak ditemukan.", code: "NOT_FOUND" } }),
          { status: 404, headers: { "Content-Type": "application/json; charset=utf-8" } }
        );
      }

      // Append security and CORS headers
      const res = new Response(response.body, response);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
        res.headers.set(k, v);
      }
      if (origin) {
        res.headers.set("Access-Control-Allow-Origin", origin);
        res.headers.set("Access-Control-Allow-Credentials", "true");
      }
      return res;
    } catch (err: any) {
      console.error("Platform API Error:", err);
      return new Response(
        JSON.stringify({
          ok: false,
          error: {
            message: err.message || "Terjadi kesalahan internal server.",
            code: err.code || "INTERNAL_ERROR",
          },
        }),
        {
          status: err.status || 500,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": origin || "*",
            "Access-Control-Allow-Credentials": "true",
            ...SECURITY_HEADERS,
          },
        }
      );
    }
  },
};
