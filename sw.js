/* VITAQU — SehatTrack Banyubiru :: Service Worker (PWA)
   Strategi:
   - Navigasi halaman (HTML): network-first, fallback cache (offline tetap terbuka)
   - Aset statis (CSS/JS lokal, gambar, font): stale-while-revalidate
   - Video besar: cache-first setelah pertama kali termuat, range request dilewatan langsung
*/
const VERSION = "vitaqu-v14";
const STATIC_CACHE = `${VERSION}-static`;
const RUNTIME_CACHE = `${VERSION}-runtime`;

const PRECACHE = [
  "./",
  "./index.html",
  "./login.html",
  "./app.html",
  "./manifest.json",
  "./favicon.png",
  "./logo.png",
  "./nutrifood.png",
  "./icons/icon-192.png",
  "./icons/notif-icon.png",
  "./icons/notif-badge.png",
  "./icons/icon-512.png",
  "./icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== STATIC_CACHE && k !== RUNTIME_CACHE)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("message", (event) => {
  if (event.data === "SKIP_WAITING") self.skipWaiting();
});

// ─── WEB PUSH: tampil walau PWA sedang ditutup ───────────────────────────────
self.addEventListener("push", (event) => {
  let payload = {
    title: "VITAQU • Pengingat Sehat",
    body: "Saatnya mencatat kebiasaan sehatmu hari ini.",
    icon: "/icons/notif-icon.png",
    badge: "/icons/notif-badge.png",
    tag: "vitaqu-reminder",
    data: { url: "/app.html?from=notification" },
  };

  if (event.data) {
    try {
      payload = { ...payload, ...event.data.json() };
    } catch {
      payload.body = event.data.text() || payload.body;
    }
  }

  const { title, ...options } = payload;
  event.waitUntil(
    self.registration.showNotification(title, {
      ...options,
      icon: options.icon || "/icons/notif-icon.png",
      badge: options.badge || "/icons/notif-badge.png",
      data: { url: "/app.html?from=notification", ...(options.data || {}) },
      actions: [{ action: "open-checklist", title: "Buka Checklist" }],
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL(
    event.notification.data?.url || "/app.html?from=notification",
    self.location.origin,
  ).href;

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then(async (windows) => {
      for (const client of windows) {
        if (new URL(client.url).origin === self.location.origin) {
          await client.navigate(target);
          return client.focus();
        }
      }
      return clients.openWindow(target);
    }),
  );
});

function isNavigation(request) {
  return request.mode === "navigate" || (request.method === "GET" && request.destination === "document");
}

function isStaticAsset(url) {
  return (
    url.pathname.startsWith("/icons/") ||
    /\.(png|jpg|jpeg|webp|svg|ico|css|js|json|woff2?)$/.test(url.pathname)
  );
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);

  // Lewati range request (video seeking) — biarkan browser handle langsung
  if (request.headers.has("range")) return;

  // CDN eksternal (font, chart.js) — passthrough cache runtime biasa
  const isExternal = url.origin !== self.location.origin;

  // 1) Navigasi halaman: network-first dengan fallback offline
  if (isNavigation(request)) {
    event.respondWith(
      fetch(request)
        .then((res) => {
          const copy = res.clone();
          caches.open(STATIC_CACHE).then((c) => c.put(request, copy));
          return res;
        })
        .catch(() =>
          caches.match(request).then((hit) => hit || caches.match("./index.html"))
        )
    );
    return;
  }

  // 2) Video hero (landscape + portrait): cache-first (di-cache penuh setelah fetch pertama)
  if (!isExternal && /hero(-portrait)?\.mp4$/.test(url.pathname)) {
    event.respondWith(
      caches.open(RUNTIME_CACHE).then(async (cache) => {
        const hit = await cache.match(url.href);
        if (hit) return hit;
        const res = await fetch(request);
        if (res.ok) cache.put(url.href, res.clone());
        return res;
      })
    );
    return;
  }

  // 3) Aset statis: stale-while-revalidate
  if (!isExternal || isStaticAsset(url)) {
    event.respondWith(
      caches.open(RUNTIME_CACHE).then(async (cache) => {
        const hit = await cache.match(request);
        const network = fetch(request)
          .then((res) => {
            if (res.ok) cache.put(request, res.clone());
            return res;
          })
          .catch(() => hit);
        return hit || network;
      })
    );
  }
});
