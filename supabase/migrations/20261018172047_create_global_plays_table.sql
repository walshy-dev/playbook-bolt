/*
# Create global shared plays table (no auth, single shared library)

1. New Tables
- `plays`
  - `id` (uuid, primary key, auto-generated)
  - `name` (text, not null) — the play name, max 40 chars
  - `cat` (text, not null) — "run" or "pass"
  - `folder` (text, nullable) — optional folder name, max 30 chars
  - `ball` (text, nullable) — ball carrier player id like "O3"
  - `showd` (boolean, default true) — whether to show defense
  - `data` (jsonb, not null) — full play object including players array
  - `updated` (timestamptz, default now()) — last modification time
  - `created` (timestamptz, default now()) — creation time

2. Security
- Enable RLS on `plays`.
- Allow anon + authenticated full CRUD because all plays are intentionally shared/public (no accounts, no sign-in).
- Four separate policies: SELECT, INSERT, UPDATE, DELETE.

3. Important Notes
- This is a single-tenant app with no authentication. Everyone sees and can edit all plays.
- The `data` jsonb column stores the complete play object (name, players, routes, etc.) to preserve the existing data shape.
- A `name_lower` column is generated from `name` for case-insensitive lookups, with a trigger to keep it in sync.
*/

CREATE TABLE IF NOT EXISTS plays (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  cat text NOT NULL DEFAULT 'pass',
  folder text,
  ball text,
  showd boolean NOT NULL DEFAULT true,
  data jsonb NOT NULL,
  name_lower text GENERATED ALWAYS AS (lower(trim(name))) STORED,
  updated timestamptz NOT NULL DEFAULT now(),
  created timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS plays_name_lower_idx ON plays (name_lower);
CREATE INDEX IF NOT EXISTS plays_cat_idx ON plays (cat);
CREATE INDEX IF NOT EXISTS plays_folder_idx ON plays (folder);

ALTER TABLE plays ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_plays" ON plays;
CREATE POLICY "anon_select_plays" ON plays FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_plays" ON plays;
CREATE POLICY "anon_insert_plays" ON plays FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_plays" ON plays;
CREATE POLICY "anon_update_plays" ON plays FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_plays" ON plays;
CREATE POLICY "anon_delete_plays" ON plays FOR DELETE
  TO anon, authenticated USING (true);
