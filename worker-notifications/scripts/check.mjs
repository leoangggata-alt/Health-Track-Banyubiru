import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const messages = JSON.parse(
  await readFile(new URL("../src/messages.json", import.meta.url), "utf8"),
);

assert.equal(messages.length, 50, "Harus tepat 50 template pesan");

const slots = new Set(["morning", "afternoon", "evening"]);
for (const [index, message] of messages.entries()) {
  assert(slots.has(message.slot), `Slot invalid pada pesan ${index + 1}`);
  assert(message.title?.trim(), `Judul kosong pada pesan ${index + 1}`);
  assert(message.body?.trim(), `Isi kosong pada pesan ${index + 1}`);
  assert(message.title.length <= 60, `Judul terlalu panjang pada pesan ${index + 1}`);
  assert(message.body.length <= 180, `Isi terlalu panjang pada pesan ${index + 1}`);
}

assert.equal(new Set(messages.map(({ title }) => title)).size, 50, "Semua judul harus unik");
assert.equal(new Set(messages.map(({ body }) => body)).size, 50, "Semua isi harus unik");

const distribution = Object.fromEntries(
  [...slots].map((slot) => [slot, messages.filter((message) => message.slot === slot).length]),
);
assert.deepEqual(distribution, { morning: 17, afternoon: 17, evening: 16 });

const schedules = [
  { slot: "morning", wib: "06:15", utc: "23:15", cron: "15 23 * * *" },
  { slot: "afternoon", wib: "14:15", utc: "07:15", cron: "15 7 * * *" },
  { slot: "evening", wib: "20:55", utc: "13:55", cron: "55 13 * * *" },
];

for (const schedule of schedules) {
  const [hour, minute] = schedule.wib.split(":").map(Number);
  const utcHour = (hour - 7 + 24) % 24;
  assert.equal(
    `${String(utcHour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`,
    schedule.utc,
    `Konversi WIB ke UTC salah untuk ${schedule.slot}`,
  );
  assert.equal(schedule.cron, `${minute} ${utcHour} * * *`);
}

console.log("✓ 50 template unik:", distribution);
console.log("✓ Jadwal WIB/UTC:", schedules);
