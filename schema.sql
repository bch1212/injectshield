-- D1 schema for PromptShield.
-- Apply with: wrangler d1 execute promptshield --file=schema.sql

CREATE TABLE IF NOT EXISTS usage (
  api_key TEXT NOT NULL,
  month   TEXT NOT NULL,        -- YYYY-MM
  count   INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (api_key, month)
);

CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key     TEXT NOT NULL,
  request_id  TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  context     TEXT,
  confidence  REAL,
  safe        INTEGER,
  threat      TEXT,
  text_len    INTEGER,
  text_sample TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_apikey_ts ON scans (api_key, ts);
CREATE INDEX IF NOT EXISTS idx_scans_threat    ON scans (threat);
