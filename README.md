# Health-Track-Banyubiru

Sistem pelacakan aktivitas siswa SMP Negeri 1 Banyubiru — Program 30 Hari Hidup Sehat.

## Struktur (v2 — split architecture)

| Halaman | Fungsi |
|---|---|
| `index.html` | Landing page premium (video hero) |
| `login.html` | Login member (siswa) |
| `app.html` | Dashboard member — khusus siswa |
| `admin/index.html` | Panel admin terpisah (deploy ke project Cloudflare Pages sendiri: health-track-admin.pages.dev) |

## Deploy

- **Main**: Cloudflare Pages → deploy root
- **Admin**: Cloudflare Pages → deploy folder `admin/`

Provide apps by Fendi Akhmad, S.Pd. — © 2026 SMP Negeri 1 Banyubiru
