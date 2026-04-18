-- DNS-RPZ Database Schema
-- PostgreSQL 14+

-- -------------------------------------------------------
-- Settings: application config stored in DB
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key         VARCHAR(64)  PRIMARY KEY,
    value       TEXT         NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- RPZ Zones: list of managed RPZ zones
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS rpz_zones (
    id                  BIGSERIAL       PRIMARY KEY,
    name                VARCHAR(255)    NOT NULL UNIQUE,   -- zone FQDN, e.g. "rpz.example.com"
    mode                VARCHAR(8)      NOT NULL DEFAULT 'slave' CHECK (mode IN ('master', 'slave')),
    master_ip           INET,                              -- primary AXFR master (slave mode only)
    master_ip_secondary INET,                              -- secondary/backup AXFR master (optional)
    master_port         SMALLINT        NOT NULL DEFAULT 53,
    tsig_key            VARCHAR(255),
    tsig_secret         TEXT,                              -- base64-encoded TSIG secret
    sync_interval       INT             NOT NULL DEFAULT 300,
    serial              BIGINT          NOT NULL DEFAULT 0,
    last_sync_at        TIMESTAMPTZ,
    last_sync_status    VARCHAR(16),                       -- success, failed, in_progress
    enabled             BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Add secondary master column for existing databases (safe to run multiple times)
ALTER TABLE rpz_zones ADD COLUMN IF NOT EXISTS master_ip_secondary INET;

-- -------------------------------------------------------
-- RPZ Records: blocked domain entries (can be millions)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS rpz_records (
    id          BIGSERIAL       PRIMARY KEY,
    zone_id     BIGINT          NOT NULL REFERENCES rpz_zones(id) ON DELETE CASCADE,
    name        VARCHAR(255)    NOT NULL,  -- domain to block, e.g. "malware.example.com"
    rtype       VARCHAR(16)     NOT NULL DEFAULT 'CNAME',
    rdata       TEXT            NOT NULL DEFAULT '.',
    ttl         INT             NOT NULL DEFAULT 300,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Critical index for DNS lookup performance (millions of rows)
CREATE UNIQUE INDEX IF NOT EXISTS idx_rpz_records_zone_name  ON rpz_records (zone_id, name);

-- The separate name-only index is no longer needed: DNS queries use the
-- in-memory index, and startup LoadAllNames queries by zone_id (covered by
-- idx_rpz_records_zone_name). Dropping it halves index-maintenance cost during AXFR sync.
DROP INDEX IF EXISTS idx_rpz_records_name;

-- -------------------------------------------------------
-- Users: dashboard authentication
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL       PRIMARY KEY,
    username        VARCHAR(64)     NOT NULL UNIQUE,
    password_hash   VARCHAR(255)    NOT NULL,
    role            VARCHAR(16)     NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer')),
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- -------------------------------------------------------
-- Sessions: cookie-based session store
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id          VARCHAR(64)     PRIMARY KEY,
    user_id     BIGINT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ     NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- -------------------------------------------------------
-- IP Filters: allowed client IPs/CIDRs for recursion
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_filters (
    id          BIGSERIAL   PRIMARY KEY,
    cidr        CIDR        NOT NULL UNIQUE,
    description TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- Sync History: AXFR sync audit log
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS sync_history (
    id              BIGSERIAL       PRIMARY KEY,
    zone_id         BIGINT          NOT NULL REFERENCES rpz_zones(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          VARCHAR(16)     NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'success', 'failed')),
    records_added   INT             NOT NULL DEFAULT 0,
    records_removed INT             NOT NULL DEFAULT 0,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sync_history_zone_id    ON sync_history (zone_id);
CREATE INDEX IF NOT EXISTS idx_sync_history_started_at ON sync_history (started_at DESC);

-- -------------------------------------------------------
-- DNS Query Log: per-query audit log for statistics
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_query_log (
    id          BIGSERIAL    PRIMARY KEY,
    client_ip   INET         NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    qtype       VARCHAR(16)  NOT NULL,
    result      VARCHAR(16)  NOT NULL CHECK (result IN ('allowed', 'blocked', 'refused')),
    upstream    VARCHAR(64),
    rtt_ms      INT,
    queried_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Safe to run on existing tables (no-op if columns already exist)
ALTER TABLE dns_query_log ADD COLUMN IF NOT EXISTS upstream VARCHAR(64);
ALTER TABLE dns_query_log ADD COLUMN IF NOT EXISTS rtt_ms   INT;

CREATE INDEX IF NOT EXISTS idx_dns_query_log_queried_at ON dns_query_log (queried_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_result     ON dns_query_log (result);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_domain     ON dns_query_log (domain);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_client_ip  ON dns_query_log (client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_query_log_upstream   ON dns_query_log (upstream);

-- -------------------------------------------------------
-- Server Stats: live counters written by dns-rpz-dns process
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS server_stats (
    key         VARCHAR(64)  PRIMARY KEY,
    value       BIGINT       NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -------------------------------------------------------
-- Default settings (first run)
-- -------------------------------------------------------
INSERT INTO settings (key, value) VALUES
    ('mode',                   'slave'),
    ('master_ip',              ''),
    ('master_port',            '53'),
    ('tsig_key',               ''),
    ('tsig_secret',            ''),
    ('sync_interval',          '86400'),
    ('web_port',               '8080'),
    ('timezone',               'UTC'),
    ('dns_upstream',           '8.8.8.8:53,8.8.4.4:53'),
    ('dns_upstream_strategy',  'roundrobin')
ON CONFLICT (key) DO NOTHING;
