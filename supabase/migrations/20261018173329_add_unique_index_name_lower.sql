/*
# Add unique index on plays.name_lower

1. Changes
- Adds a unique index on the generated `name_lower` column of the `plays` table.
- This enables upsert-by-name: the frontend can `INSERT ... ON CONFLICT (name_lower) DO UPDATE`
  so saving a play with an existing name updates it instead of creating a duplicate.
2. Security
- No policy changes. RLS stays as-is (anon+authenticated full CRUD, single-tenant shared plays).
3. Notes
- `name_lower` is a GENERATED ALWAYS column computed from `lower(trim(name))`.
- Generated stored columns can participate in unique indexes in Postgres.
*/

CREATE UNIQUE INDEX IF NOT EXISTS plays_name_lower_key ON plays (name_lower);