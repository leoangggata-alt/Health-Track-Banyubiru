// platform-api/tests/verify.mjs
// End-to-end integration tests for Super Admin and School Admin licensing

import { base32Decode } from '../src/crypto.ts';

const API_URL = process.env.API_URL || 'https://vitaqu-platform-api.abel-lab-security-2026.workers.dev';

// Helper to generate current TOTP code for testing
async function getTotpCode(secretBase32) {
  const timeStep = 30;
  const currentStep = Math.floor(Date.now() / 1000 / timeStep);
  const keyBytes = base32Decode(secretBase32);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, 0, false);
  view.setUint32(4, currentStep, false);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const binCode = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, '0');
}

async function runTests() {
  console.log('--- MEMULAI INTEGRATION TEST VITAQU LICENSING ---');
  let superCookie = '';
  let superCsrf = '';
  let adminCookie = '';
  let adminCsrf = '';

  const superUsername = 'superadmin';
  const superPassword = 'CxutXJLJ8d%RP*@S';
  const superTotpSecret = 'SKUJVDYB7G5CTHFIEPOTP4633HVZRKVS';

  // 1. Super Admin Login
  console.log('1. Menguji Super Admin Login dengan TOTP valid...');
  const totpCode = await getTotpCode(superTotpSecret);
  const loginRes = await fetch(`${API_URL}/api/super/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: superUsername,
      password: superPassword,
      totp: totpCode,
    }),
  });

  const loginData = await loginRes.json();
  if (!loginRes.ok || !loginData.ok) {
    throw new Error(`Super admin login gagal: ${JSON.stringify(loginData)}`);
  }
  const setCookieHeader = loginRes.headers.get('set-cookie');
  if (!setCookieHeader) throw new Error('Cookie vitaqu_super_session tidak diterima.');
  superCookie = setCookieHeader.split(';')[0];
  superCsrf = loginData.session.csrfToken;
  console.log('   ✅ Super admin login berhasil. CSRF:', superCsrf);

  // 2. Super Admin Session Check
  console.log('2. Menguji Super Admin Session Check...');
  const sessionRes = await fetch(`${API_URL}/api/super/session`, {
    headers: { Cookie: superCookie },
  });
  const sessionData = await sessionRes.json();
  if (!sessionRes.ok || !sessionData.ok) {
    throw new Error(`Super admin session check gagal: ${JSON.stringify(sessionData)}`);
  }
  console.log('   ✅ Super admin session aktif:', sessionData.user.username);

  // 3. Super Admin Create School & License
  console.log('3. Menguji Super Admin membuat Lisensi Sekolah baru...');
  const schoolCode = `TEST${Math.floor(1000 + Math.random() * 9000)}`;
  const createRes = await fetch(`${API_URL}/api/super/licenses`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: superCookie,
      'x-csrf-token': superCsrf,
    },
    body: JSON.stringify({
      school_name: 'SMP Negeri 1 Uji Coba',
      school_code: schoolCode,
      school_level: 'SMP',
      principal_name: 'Drs. H. Penguji, M.Pd.',
      duration: '90',
      max_admins: 2,
      initial_admin_username: 'admin.uji',
    }),
  });

  const createData = await createRes.json();
  if (!createRes.ok || !createData.ok) {
    throw new Error(`Pembuatan lisensi gagal: ${JSON.stringify(createData)}`);
  }
  const { licenseKey, username: adminUsername, initialPassword: adminPassword } = createData.credentials;
  const licenseId = createData.license.id;
  console.log('   ✅ Lisensi sekolah berhasil dibuat!');
  console.log(`      Kode Sekolah : ${schoolCode}`);
  console.log(`      License Key  : ${licenseKey}`);
  console.log(`      Admin User   : ${adminUsername}`);
  console.log(`      Initial Pass : ${adminPassword}`);
  console.log(`      Expires At   : ${createData.license.expiresAt}`);

  // 4. List Licenses & Dashboard Stats
  console.log('4. Menguji Super Admin List Licenses & Summary...');
  const listRes = await fetch(`${API_URL}/api/super/licenses?q=${schoolCode}`, {
    headers: { Cookie: superCookie },
  });
  const listData = await listRes.json();
  if (!listRes.ok || !listData.ok || listData.items.length === 0) {
    throw new Error(`Pencarian lisensi gagal: ${JSON.stringify(listData)}`);
  }
  console.log(`   ✅ Ditemukan lisensi: ${listData.items[0].school.name}, Total Sekolah: ${listData.summary.totalSchools}, Aktif: ${listData.summary.active}`);

  // 5. School Admin Login with INVALID License Key
  console.log('5. Menguji School Admin Login dengan Kunci Lisensi SALAH (harus gagal)...');
  const badLoginRes = await fetch(`${API_URL}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      licenseKey: 'VITAQU-WRONG-KEY-1234-5678',
      username: adminUsername,
      password: adminPassword,
    }),
  });
  const badLoginData = await badLoginRes.json();
  if (badLoginRes.ok || badLoginData.ok) {
    throw new Error('Login harusnya gagal dengan lisensi salah!');
  }
  console.log('   ✅ Penolakan lisensi salah berhasil:', badLoginData.error.message);

  // 6. School Admin Login with VALID License Key
  console.log('6. Menguji School Admin Login dengan Kunci Lisensi BENAR...');
  const adminLoginRes = await fetch(`${API_URL}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      licenseKey,
      username: adminUsername,
      password: adminPassword,
    }),
  });
  const adminLoginData = await adminLoginRes.json();
  if (!adminLoginRes.ok || !adminLoginData.ok) {
    throw new Error(`Admin login gagal: ${JSON.stringify(adminLoginData)}`);
  }
  const adminSetCookie = adminLoginRes.headers.get('set-cookie');
  if (!adminSetCookie) throw new Error('Cookie vitaqu_admin_session tidak diterima.');
  adminCookie = adminSetCookie.split(';')[0];
  adminCsrf = adminLoginData.session.csrfToken;
  console.log('   ✅ School admin berhasil masuk. mustChangePassword:', adminLoginData.session.mustChangePassword);

  // 7. School Admin Session Check
  console.log('7. Menguji School Admin Session Check...');
  const adminSessionRes = await fetch(`${API_URL}/api/admin/session`, {
    headers: { Cookie: adminCookie },
  });
  const adminSessionData = await adminSessionRes.json();
  if (!adminSessionRes.ok || !adminSessionData.ok) {
    throw new Error(`Admin session check gagal: ${JSON.stringify(adminSessionData)}`);
  }
  console.log(`   ✅ Sesi admin valid. Sekolah: ${adminSessionData.school.name}, Sisa Hari: ${adminSessionData.license.daysRemaining}`);

  // 8. School Admin Add Class
  console.log('8. Menguji School Admin menambah kelas...');
  const classRes = await fetch(`${API_URL}/api/admin/classes`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: adminCookie,
      'x-csrf-token': adminCsrf,
    },
    body: JSON.stringify({ name: 'Kelas 7A Eksperimen' }),
  });
  const classData = await classRes.json();
  if (!classRes.ok || !classData.ok) {
    throw new Error(`Gagal tambah kelas: ${JSON.stringify(classData)}`);
  }
  console.log('   ✅ Kelas berhasil dibuat:', classData.class.name);

  // 9. Super Admin Revoke License
  console.log('9. Menguji Super Admin mencabut (revoke) lisensi...');
  const revokeRes = await fetch(`${API_URL}/api/super/licenses/${licenseId}/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: superCookie,
      'x-csrf-token': superCsrf,
    },
    body: JSON.stringify({ reason: 'Uji coba penonaktifan lisensi' }),
  });
  const revokeData = await revokeRes.json();
  if (!revokeRes.ok || !revokeData.ok) {
    throw new Error(`Revoke gagal: ${JSON.stringify(revokeData)}`);
  }
  console.log('   ✅ Lisensi berhasil dicabut oleh super admin.');

  // 10. School Admin access with revoked license (MUST BE BLOCKED WITH 403)
  console.log('10. Menguji School Admin mengakses sistem setelah lisensi dicabut (harus diblokir 403)...');
  const blockedRes = await fetch(`${API_URL}/api/admin/session`, {
    headers: { Cookie: adminCookie },
  });
  const blockedData = await blockedRes.json();
  if (blockedRes.status !== 403) {
    throw new Error(`Akses lisensi dicabut harusnya 403, tapi dapat ${blockedRes.status}: ${JSON.stringify(blockedData)}`);
  }
  console.log('   ✅ Akses panel admin berhasil langsung diblokir:', blockedData.error.message);

  // 11. Super Admin Reactivate License
  console.log('11. Menguji Super Admin mengaktifkan kembali (reactivate) lisensi...');
  const reactivateRes = await fetch(`${API_URL}/api/super/licenses/${licenseId}/reactivate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: superCookie,
      'x-csrf-token': superCsrf,
    },
    body: JSON.stringify({}),
  });
  const reactivateData = await reactivateRes.json();
  if (!reactivateRes.ok || !reactivateData.ok) {
    throw new Error(`Reactivate gagal: ${JSON.stringify(reactivateData)}`);
  }
  console.log('   ✅ Lisensi berhasil diaktifkan kembali.');

  // 12. School Admin can access session again
  console.log('12. Menguji School Admin mengakses kembali setelah reaktivasi...');
  const restoredRes = await fetch(`${API_URL}/api/admin/session`, {
    headers: { Cookie: adminCookie },
  });
  const restoredData = await restoredRes.json();
  if (!restoredRes.ok || !restoredData.ok) {
    throw new Error(`Akses setelah reaktivasi gagal: ${JSON.stringify(restoredData)}`);
  }
  console.log('   ✅ Akses panel admin pulih:', restoredData.school.name);

  console.log('\n🎉 SEMUA 12 SKENARIO INTEGRATION TEST BERHASIL 100%!');
}

runTests().catch(err => {
  console.error('\n❌ TEST GAGAL:', err.message);
  process.exit(1);
});
