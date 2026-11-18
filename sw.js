/* VITAQU — SehatTrack Banyubiru :: Service Worker (PWA)
   Strategi:
   - Navigasi halaman (HTML): network-first, fallback cache (offline tetap terbuka)
   - Aset statis (CSS/JS lokal, gambar, font): stale-while-revalidate
   - Video besar: cache-first setelah pertama kali termuat, range request dilewatan langsung
*/
const VERSION = "vitaqu-v9";
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
