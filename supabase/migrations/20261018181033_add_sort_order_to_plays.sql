/*
# Add sort_order column to plays

1. Changes
- Adds `sort_order` (integer, nullable) to `plays`.
  When null, plays fall back to alphabetical order.
  When set, plays are ordered by sort_order first, then name.
- Backfills `sort_order` for existing plays by assigning alphabetical
  order within each folder (NULL folder treated as its own bucket), so
  nothing changes about the current ordering on first load.

2. Indexes
- Adds `plays_sort_idx` on (folder, sort_order, name_lower) so the
  load-order query is fast.

3. Security
- No policy changes. RLS is already enabled with anon+authenticated
  full CRUD (single-tenant shared library, no sign-in).
*/

ALTER TABLE plays ADD COLUMN IF NOT EXISTS sort_order integer;

CREATE INDEX IF NOT EXISTS plays_sort_idx ON plays (folder, sort_order, name_lower);

-- Backfill sort_order alphabetically within each folder bucket.
-- NULL folder gets its own sequence; each named folder gets its own.
WITH ranked AS (
  SELECT id,
         ROW_NUMBER() OVER (
           PARTITION BY COALESCE(folder, '\x00__null__')
           ORDER BY lower(trim(name))
         ) AS rn
  FROM plays
)
UPDATE plays p
SET sort_order = r.rn
FROM ranked r
WHERE p.id = r.id
  AND p.sort_order IS NULL;