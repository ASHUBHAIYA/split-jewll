-- Run once:  npx wrangler d1 execute jwellery_db --remote --file=schema.sql
-- D1 now only stores the admin PIN and licenses. The job queue and the bridge heartbeat live in the
-- RelayRoom Durable Object (no D1 writes while the bridge is idle).

CREATE TABLE IF NOT EXISTS admin_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS licenses (
  license_key TEXT PRIMARY KEY,
  store_name TEXT NOT NULL,
  contact_info TEXT DEFAULT '',
  duration_months INTEGER DEFAULT 12,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  machine_id TEXT DEFAULT '',
  status TEXT DEFAULT 'active',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Old relay tables: no longer used. Dropping them removes the growing table that was being scanned on every poll.
DROP TABLE IF EXISTS relay_queue;
DROP TABLE IF EXISTS daemon_heartbeats;
