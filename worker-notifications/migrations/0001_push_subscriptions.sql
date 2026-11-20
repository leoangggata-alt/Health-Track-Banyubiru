CREATE TABLE IF NOT EXISTS push_subscriptions (
  endpoint_hash TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  expiration_time INTEGER,
  role TEXT NOT NULL CHECK (role IN ('student', 'teacher')) DEFAULT 'student',
  morning_enabled INTEGER NOT NULL DEFAULT 1 CHECK (morning_enabled IN (0, 1)),
  afternoon_enabled INTEGER NOT NULL DEFAULT 1 CHECK (afternoon_enabled IN (0, 1)),
  evening_enabled INTEGER NOT NULL DEFAULT 1 CHECK (evening_enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_test_at TEXT,
  last_sent_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_push_schedule
ON push_subscriptions (morning_enabled, afternoon_enabled, evening_enabled);
