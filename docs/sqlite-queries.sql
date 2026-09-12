-- Open advisories.sqlite with any SQLite client.
-- These SELECTs do not change the signed database.
-- Schema v5: records.json is zlib-compressed Record JSON, including full details
-- and affected[].versions. Lookup and matching decode that JSON.
-- records.details is retained for compatibility but is always ''.
-- details_truncated describes the upstream Record, not a SQL preview.
-- affected.versions_blob is one zlib-compressed JSON array per affected row
-- (including [] for no explicit versions). There is no affected_versions table.
-- SQLite has no built-in zlib decoder: use bscan db lookup/show for full details
-- and versions, or decompress these blobs in your SQLite client's host language.
-- Timestamps remain their original RFC3339 text (and NULL when absent).

-- Inspect all normalized catalog tables and indexes.
SELECT type, name, tbl_name
FROM sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type, name;

-- Local timestamps are distinct from upstream publication/modification times.
-- Legacy records may have NULL added_at because first ingestion is unknown.
SELECT id, source, published_at, modified_at, added_at, last_seen_at,
       details_truncated, summary
FROM records
ORDER BY id
LIMIT 20;

-- Find advisories for an exact ecosystem/package pair using the package index.
SELECT r.id, r.summary
FROM records AS r
JOIN package_affected AS p ON p.record_id = r.id
WHERE p.base_ecosystem = 'npm' AND p.name = 'lodash'
GROUP BY r.id, r.summary
ORDER BY r.id;

-- Retrieve both direct advisory IDs and IDs known through aliases.
SELECT id, summary
FROM records
WHERE id = 'CVE-2021-23337'
   OR id IN (SELECT record_id FROM aliases WHERE alias = 'CVE-2021-23337');

-- See the exact version boundaries, preserving event order.
SELECT a.record_id, a.ecosystem, a.package_name, g.range_type,
       e.introduced, e.fixed, e.last_affected, e.limit_version
FROM affected AS a
JOIN affected_ranges AS g ON g.affected_id = a.id
JOIN range_events AS e ON e.range_id = g.id
WHERE a.base_ecosystem = 'npm' AND a.normalized_name = 'lodash'
ORDER BY a.record_id, g.id, e.ordinal;

-- Per-record feed origin. An empty URL means legacy provenance is unknown.
SELECT record_id, source, url
FROM record_sources
ORDER BY record_id, source, url
LIMIT 20;

-- Inspect storage for explicit version lists without expanding millions of rows.
SELECT record_id, ecosystem, package_name, length(versions_blob) AS versions_bytes
FROM affected
WHERE base_ecosystem = 'npm' AND normalized_name = 'lodash'
ORDER BY record_id, ordinal;
