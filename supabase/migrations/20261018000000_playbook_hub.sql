-- 49ers Playbook Hub, Bolt version: the same rules as server.js, kept inside the Bolt (Supabase/Postgres) database.
-- The app never touches the tables directly. It calls the hub_* functions below, which check the team code,
-- the coach's PIN and sign-in token, and that coaches only change their own plays.
-- Stores only first names, hashed PINs and plays. No emails, no children's information.

create extension if not exists pgcrypto;

create table if not exists hub_teams (
  id text primary key,
  name text not null,
  code_hash text not null unique,
  created timestamptz not null default now()
);
create table if not exists hub_coaches (
  id text primary key,
  team_id text not null references hub_teams(id) on delete cascade,
  name text not null,
  pin_hash text not null,
  created timestamptz not null default now()
);
create table if not exists hub_tokens (
  token text primary key,
  coach_id text not null references hub_coaches(id) on delete cascade,
  created timestamptz not null default now()
);
create table if not exists hub_plays (
  id text primary key,
  team_id text not null references hub_teams(id) on delete cascade,
  owner_id text not null references hub_coaches(id) on delete cascade,
  updated timestamptz not null default now(),
  data jsonb not null
);
create table if not exists hub_attempts (
  key text not null,
  at timestamptz not null default now()
);
create table if not exists hub_state (
  id int primary key default 1 check (id = 1),
  rev bigint not null default 0
);
insert into hub_state (id, rev) values (1, 0) on conflict (id) do nothing;
create index if not exists hub_plays_team on hub_plays (team_id);
create index if not exists hub_plays_owner on hub_plays (owner_id);
create index if not exists hub_attempts_key on hub_attempts (key, at);

-- Nobody reads or writes the tables directly from the app; only through the functions.
alter table hub_teams enable row level security;
alter table hub_coaches enable row level security;
alter table hub_tokens enable row level security;
alter table hub_plays enable row level security;
alter table hub_attempts enable row level security;
alter table hub_state enable row level security;
revoke all on hub_teams, hub_coaches, hub_tokens, hub_plays, hub_attempts, hub_state from anon, authenticated;

-- Any change to shared plays (including rows deleted by hand in the Tables screen) bumps the library version.
create or replace function hub_bump() returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin update hub_state set rev = rev + 1 where id = 1; return null; end $$;
drop trigger if exists hub_plays_bump on hub_plays;
create trigger hub_plays_bump after insert or update or delete on hub_plays for each statement execute function hub_bump();

-- ---------------------------------------------------------------- helpers (not callable from the app)
create or replace function hub_sha(t text) returns text language sql immutable set search_path = public, extensions as $$
  select encode(digest(convert_to(t, 'UTF8'), 'sha256'), 'hex') $$;
create or replace function hub_slug(t text) returns text language sql immutable as $$
  select coalesce(nullif(left(regexp_replace(regexp_replace(lower(t), '[^a-z0-9]+', '-', 'g'), '^-+|-+$', '', 'g'), 40), ''), 'play') $$;
create or replace function hub_err(msg text, status int) returns jsonb language sql immutable as $$
  select jsonb_build_object('error', msg, 'status', status) $$;
create or replace function hub_ip() returns text language sql stable as $$
  select coalesce(nullif(trim(split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''), ',', 1)), ''), 'unknown') $$;
-- the signed-in coach for a token (tokens last 180 days), or null
create or replace function hub_who(p_token text) returns hub_coaches language sql stable security definer set search_path = public, extensions as $$
  select c.* from hub_tokens t join hub_coaches c on c.id = t.coach_id
  where t.token = p_token and p_token ~ '^[a-f0-9]{48}$' and t.created > now() - interval '180 days' $$;

-- ---------------------------------------------------------------- the API (same answers as server.js)
create or replace function hub_health() returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('ok', true, 'name', '49ers Playbook Hub', 'teams', (select count(*) from hub_teams)) $$;

create or replace function hub_join(p_code text, p_name text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  ip text := hub_ip(); nm text; pin text := coalesce(p_pin, ''); t hub_teams; c hub_coaches; cid text; tok text;
begin
  delete from hub_attempts where at < now() - interval '15 minutes';
  insert into hub_attempts (key) values ('join:' || ip);
  if (select count(*) from hub_attempts where key = 'join:' || ip) > 12 then
    return hub_err('Too many tries. Wait a few minutes and try again.', 429);
  end if;
  nm := regexp_replace(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'), '^ | $', '', 'g');
  if nm !~ '^[A-Za-z0-9][A-Za-z0-9 .''-]{1,23}$' then return hub_err('Use a name of 2 to 24 letters or numbers.', 400); end if;
  if pin !~ '^[A-Za-z0-9]{4,12}$' then return hub_err('Your PIN should be 4 to 12 letters or numbers.', 400); end if;
  select * into t from hub_teams where code_hash = hub_sha('team:' || trim(coalesce(p_code, '')));
  if t.id is null then return hub_err('That team code isn''t right.', 403); end if;
  cid := left(hub_sha(t.id || ':' || lower(nm)), 12);
  select * into c from hub_coaches where id = cid;
  if c.id is not null then
    if c.pin_hash <> crypt(pin, c.pin_hash) then return hub_err('That name is already taken, and the PIN doesn''t match.', 403); end if;
  else
    insert into hub_coaches (id, team_id, name, pin_hash) values (cid, t.id, nm, crypt(pin, gen_salt('bf', 8))) returning * into c;
  end if;
  tok := encode(gen_random_bytes(24), 'hex');
  insert into hub_tokens (token, coach_id) values (tok, c.id);
  delete from hub_tokens where created < now() - interval '180 days';
  return jsonb_build_object('token', tok, 'coach', jsonb_build_object('id', c.id, 'name', c.name), 'team', jsonb_build_object('id', t.id, 'name', t.name));
end $$;

create or replace function hub_me(p_token text) returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare c hub_coaches := hub_who(p_token); t hub_teams;
begin
  if c.id is null then return hub_err('Please join the team again.', 401); end if;
  select * into t from hub_teams where id = c.team_id;
  return jsonb_build_object('coach', jsonb_build_object('id', c.id, 'name', c.name), 'team', jsonb_build_object('id', t.id, 'name', t.name));
end $$;

create or replace function hub_logout(p_token text) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if (hub_who(p_token)).id is null then return hub_err('Please join the team again.', 401); end if;
  delete from hub_tokens where token = p_token;
  return jsonb_build_object('ok', true);
end $$;

create or replace function hub_plays(p_token text, p_rev bigint default null) returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare c hub_coaches := hub_who(p_token); r bigint := (select rev from hub_state where id = 1);
begin
  if c.id is null then return hub_err('Please join the team again.', 401); end if;
  if p_rev is not null and p_rev = r then return jsonb_build_object('rev', r, 'same', true); end if;
  return jsonb_build_object('rev', r, 'plays', coalesce((
    select jsonb_agg(jsonb_build_object('id', p.id, 'owner', jsonb_build_object('id', p.owner_id, 'name', coalesce(o.name, 'A coach')),
                                        'updated', (extract(epoch from p.updated) * 1000)::bigint, 'data', p.data) order by p.id)
    from hub_plays p left join hub_coaches o on o.id = p.owner_id where p.team_id = c.team_id), '[]'::jsonb));
end $$;

-- Shared plays are checked here (shape, sizes, owner) and checked again by every app (cleanPlay) before they are opened or copied.
create or replace function hub_put_play(p_token text, p_id text, p_data jsonb) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare c hub_coaches := hub_who(p_token); nm text; pl jsonb; out jsonb;
begin
  if c.id is null then return hub_err('Please join the team again.', 401); end if;
  if coalesce(p_id, '') !~ '^[a-f0-9]{12}-[a-z0-9-]{1,40}$' then return hub_err('Not found.', 404); end if;
  if left(p_id, 13) <> c.id || '-' then return hub_err('You can only change your own plays.', 403); end if;
  if p_data is null or octet_length(p_data::text) > 300 * 1024 then return hub_err('That is too big to save.', 413); end if;
  if jsonb_typeof(p_data) <> 'object' or jsonb_typeof(p_data -> 'name') <> 'string' or jsonb_typeof(p_data -> 'players') <> 'array' then
    return hub_err('That play doesn''t look right.', 400); end if;
  nm := left(regexp_replace(p_data ->> 'name', '^\s+|\s+$', '', 'g'), 40);
  select coalesce(jsonb_agg(e order by n), '[]'::jsonb) into pl from (
    select e, n from jsonb_array_elements(p_data -> 'players') with ordinality as x(e, n) where n <= 12
  ) s where jsonb_typeof(e) = 'object' and coalesce(e ->> 'id', '') ~ '^[OD][0-9]$';
  if nm = '' or jsonb_array_length(pl) = 0 then return hub_err('That play doesn''t look right.', 400); end if;
  if p_id <> c.id || '-' || hub_slug(nm) then return hub_err('The play id doesn''t match its name.', 400); end if;
  if not exists (select 1 from hub_plays where id = p_id) and (select count(*) from hub_plays where owner_id = c.id) >= 300 then
    return hub_err('That''s the most plays one coach can share.', 400); end if;
  out := jsonb_build_object('name', nm, 'showD', coalesce(p_data -> 'showD', 'true'::jsonb) <> 'false'::jsonb, 'players', pl);
  if p_data ->> 'cat' in ('run', 'pass') then out := out || jsonb_build_object('cat', p_data ->> 'cat'); end if;
  if coalesce(p_data ->> 'ball', '') ~ '^O[0-9]$' then out := out || jsonb_build_object('ball', p_data ->> 'ball'); end if;
  if jsonb_typeof(p_data -> 'folder') = 'string' and trim(p_data ->> 'folder') <> '' then out := out || jsonb_build_object('folder', left(trim(p_data ->> 'folder'), 30)); end if;
  insert into hub_plays (id, team_id, owner_id, updated, data) values (p_id, c.team_id, c.id, now(), out)
    on conflict (id) do update set updated = now(), data = excluded.data;
  return jsonb_build_object('ok', true, 'id', p_id);
end $$;

create or replace function hub_delete_play(p_token text, p_id text) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare c hub_coaches := hub_who(p_token);
begin
  if c.id is null then return hub_err('Please join the team again.', 401); end if;
  if coalesce(p_id, '') !~ '^[a-f0-9]{12}-[a-z0-9-]{1,40}$' then return hub_err('Not found.', 404); end if;
  if left(p_id, 13) <> c.id || '-' then return hub_err('You can only change your own plays.', 403); end if;
  delete from hub_plays where id = p_id and owner_id = c.id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------- admin (run by you in Bolt, never from the app)
-- Add a team, or rename it:   select hub_admin_add_team('515 Flag Football', 'your-team-code');
create or replace function hub_admin_add_team(p_name text, p_code text) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare h text := hub_sha('team:' || trim(coalesce(p_code, ''))); t hub_teams;
begin
  if trim(coalesce(p_name, '')) = '' or length(trim(coalesce(p_code, ''))) < 6 then return hub_err('Give a name and a code of at least 6 characters.', 400); end if;
  select * into t from hub_teams where code_hash = h;
  if t.id is null then
    insert into hub_teams (id, name, code_hash) values ('t' || encode(gen_random_bytes(4), 'hex'), left(trim(p_name), 40), h) returning * into t;
  else update hub_teams set name = left(trim(p_name), 40) where id = t.id returning * into t; end if;
  return jsonb_build_object('team', jsonb_build_object('id', t.id, 'name', t.name));
end $$;
-- Change a team's code (signed-in coaches stay signed in):   select hub_admin_change_code('old-code', 'new-code');
create or replace function hub_admin_change_code(p_old text, p_new text) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(trim(coalesce(p_new, ''))) < 6 then return hub_err('The new code needs at least 6 characters.', 400); end if;
  update hub_teams set code_hash = hub_sha('team:' || trim(p_new)) where code_hash = hub_sha('team:' || trim(coalesce(p_old, '')));
  if not found then return hub_err('No team has that old code.', 404); end if;
  return jsonb_build_object('ok', true);
end $$;
-- Remove a coach and everything they shared: delete their row in the hub_coaches table (plays and sign-ins go with it).

-- ---------------------------------------------------------------- who may call what
revoke execute on function hub_bump(), hub_sha(text), hub_slug(text), hub_err(text, int), hub_ip(), hub_who(text),
  hub_admin_add_team(text, text), hub_admin_change_code(text, text),
  hub_health(), hub_join(text, text, text), hub_me(text), hub_logout(text), hub_plays(text, bigint),
  hub_put_play(text, text, jsonb), hub_delete_play(text, text) from public, anon, authenticated;
grant execute on function hub_health(), hub_join(text, text, text), hub_me(text), hub_logout(text), hub_plays(text, bigint),
  hub_put_play(text, text, jsonb), hub_delete_play(text, text) to anon, authenticated;
