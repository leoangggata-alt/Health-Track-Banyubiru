// platform-api/scripts/bootstrap.mjs
// One-time bootstrap script for Super Admin

import fs from 'node:fs';
import path from 'node:path';

const API_URL = process.env.API_URL || 'https://vitaqu-platform-api.abel-lab-security-2026.workers.dev';
const CREDENTIALS_PATH = 'E:\\vitaqiu\\superadmin-credentials.txt';

async function bootstrap() {
  console.log(`Menghubungi bootstrap endpoint di ${API_URL}...`);
  const res = await fetch(`${API_URL}/api/super/bootstrap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'superadmin',
    }),
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    console.error('Bootstrap gagal:', data);
    process.exit(1);
  }

  const { credentials } = data;
  const content = `=====================================================
VITAQU CONTROL - KREDENSIAL BOOTSTRAP SUPER ADMIN
Waktu: ${new Date().toISOString()}
=====================================================

Username       : ${credentials.username}
Password       : ${credentials.password}
TOTP Secret    : ${credentials.totpSecret}
TOTP Auth URI  : ${credentials.totpUri}

PANDUAN MASUK:
1. Simpan password di pengelola password yang aman.
2. Tambahkan akun di Google Authenticator atau aplikasi TOTP:
   - Masukkan Secret: ${credentials.totpSecret}
   - Atau import URI: ${credentials.totpUri}
3. Masuk ke portal Super Admin di https://vitaqu-superadmin.pages.dev
   atau http://localhost:8931/superadmin/
=====================================================
`;

  fs.writeFileSync(CREDENTIALS_PATH, content, 'utf8');
  console.log('✅ Super admin berhasil dibuat!');
  console.log(`Kredensial disimpan di: ${CREDENTIALS_PATH}`);
  console.log(`Username: ${credentials.username}`);
  console.log(`Password: ${credentials.password}`);
  console.log(`TOTP Secret: ${credentials.totpSecret}`);
}

bootstrap().catch(err => {
  console.error('Error saat bootstrap:', err);
  process.exit(1);
});
