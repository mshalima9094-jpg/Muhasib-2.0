-- মুহাসিব — Cloudflare D1 ডাটাবেস স্কিমা (একবার চালালেই হবে; আবার চালালেও সমস্যা নেই)
CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,
  ident TEXT UNIQUE NOT NULL,
  type TEXT,
  name TEXT,
  salt TEXT,
  hash TEXT,
  iter INTEGER,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER,
  approved_at INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  th TEXT PRIMARY KEY,
  uid TEXT NOT NULL,
  exp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_uid ON sessions(uid);
CREATE TABLE IF NOT EXISTS items (
  uid TEXT NOT NULL,
  k TEXT NOT NULL,
  part INTEGER NOT NULL DEFAULT 0,
  v TEXT NOT NULL DEFAULT '',
  t INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  del INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (uid, k, part)
);
CREATE INDEX IF NOT EXISTS items_ts ON items(uid, ts);
CREATE TABLE IF NOT EXISTS rl (
  k TEXT PRIMARY KEY,
  c INTEGER NOT NULL,
  reset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT
);
