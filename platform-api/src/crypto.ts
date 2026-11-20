// platform-api/src/crypto.ts
// Native WebCrypto utilities for PBKDF2, TOTP, SHA-256, and secure key generation

export async function sha256(text: string): Promise<string> {
  const enc = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function generateSalt(length = 16): string {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function pbkdf2(password: string, saltHex: string, iterations = 100000): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const salt = new Uint8Array(
    (saltHex.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(derived))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function verifyPassword(password: string, saltHex: string, expectedHash: string): Promise<boolean> {
  const hash = await pbkdf2(password, saltHex);
  return timingSafeEqual(hash, expectedHash);
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function generateRandomToken(bytes = 32): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Generates license key: VITAQU-XXXX-XXXX-XXXX-XXXX (16 chars entropy, easy to read, no 0/O, 1/I)
const LICENSE_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
export function generateLicenseKey(): string {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  let raw = "";
  for (let i = 0; i < 16; i++) {
    raw += LICENSE_CHARS[arr[i] % LICENSE_CHARS.length];
  }
  return `VITAQU-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

// Generates temporary password with letters, digits, and symbols
export function generateInitialPassword(length = 14): string {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnpqrstuvwxyz";
  const digits = "23456789";
  const symbols = "@#%*";
  const all = upper + lower + digits + symbols;
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  // Ensure at least one from each set
  let res = [
    upper[arr[0] % upper.length],
    lower[arr[1] % lower.length],
    digits[arr[2] % digits.length],
    symbols[arr[3] % symbols.length],
  ];
  for (let i = 4; i < length; i++) {
    res.push(all[arr[i] % all.length]);
  }
  // Shuffle
  for (let i = res.length - 1; i > 0; i--) {
    const j = arr[i] % (i + 1);
    [res[i], res[j]] = [res[j], res[i]];
  }
  return res.join("");
}

// Base32 Alphabet RFC 4648
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTotpSecret(bytes = 20): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let res = "";
  let bits = 0;
  let val = 0;
  for (let i = 0; i < arr.length; i++) {
    val = (val << 8) | arr[i];
    bits += 8;
    while (bits >= 5) {
      res += BASE32_ALPHABET[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    res += BASE32_ALPHABET[(val << (5 - bits)) & 31];
  }
  return res;
}

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/[\s-]/g, "");
  let bits = 0;
  let val = 0;
  const out: number[] = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function verifyTotp(
  secretBase32: string,
  token: string,
  windowSteps = 1,
  timeStep = 30
): Promise<boolean> {
  const cleanToken = token.trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;
  const currentStep = Math.floor(Date.now() / 1000 / timeStep);
  const keyBytes = base32Decode(secretBase32);
  if (keyBytes.length === 0) return false;

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    const step = currentStep + offset;
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, 0, false);
    view.setUint32(4, step, false);

    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buf));
    const off = sig[sig.length - 1] & 0x0f;
    const binCode =
      ((sig[off] & 0x7f) << 24) |
      ((sig[off + 1] & 0xff) << 16) |
      ((sig[off + 2] & 0xff) << 8) |
      (sig[off + 3] & 0xff);

    const expected = String(binCode % 1000000).padStart(6, "0");
    if (timingSafeEqual(expected, cleanToken)) {
      return true;
    }
  }
  return false;
}
