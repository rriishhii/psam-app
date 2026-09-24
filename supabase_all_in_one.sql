-- =====================================================================================
-- PSAM: complete Supabase setup (one file). Paste into Dashboard -> SQL Editor and run once.
-- Safe to re-run, and also upgrades a project that used the earlier separate scripts.
--
-- What it sets up
--   1. Tables: profiles (roles + approval), records, recycle_bin, drafts, api_log (rate limiting),
--      access_log (who looked at / changed which property), record_audit (previous versions)
--   2. Roles: every new account starts LOCKED (active = false) until an admin approves it;
--      approved accounts are field_staff; only admins can change roles or approve/disable people
--   3. Lockdown: records / recycle_bin cannot be touched directly by anyone
--   4. Server functions: lookups, saves, validation, duplicate refusal, rate limits, reports
--   5. Explicit deny-all policies on the locked tables (states the intent and silences the Supabase advisor)
-- =====================================================================================


-- ======================= 1. Tables, roles and profile/draft access =======================
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'field_staff' check (role in ('admin', 'field_staff')),
  active boolean not null default false,          -- false = signed up but not yet approved (or disabled) by an admin
  created_at timestamptz not null default now()
);
create table if not exists public.records     (k text primary key, j text not null);
create table if not exists public.recycle_bin (k text primary key, j text not null);
create table if not exists public.drafts      (uid uuid primary key references auth.users(id) on delete cascade, j text not null);

-- Upgrade path: accounts that already existed before approval was introduced stay active (so nobody is locked out
-- by this upgrade); every account created from now on starts locked. This block only runs once.
do $$ begin
  if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'profiles' and column_name = 'active') then
    alter table public.profiles add column active boolean not null default false;
    update public.profiles set active = true;
  end if;
end $$;

-- Role helpers (security definer so policies can read profiles without recursion).
-- Both require an APPROVED (active) account, so signing up alone gives no access to anything.
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.profiles where id = auth.uid() and active) $$;
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and active) $$;

-- Every new account gets a field_staff profile. The client can never create or change its own role.
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as
$$ begin insert into public.profiles (id, email) values (new.id, new.email); return new; end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.profiles    enable row level security;
alter table public.records     enable row level security;
alter table public.recycle_bin enable row level security;
alter table public.drafts      enable row level security;

drop policy if exists "read own profile or admin" on public.profiles;
create policy "read own profile or admin" on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
drop policy if exists "admins change roles" on public.profiles;
create policy "admins change roles" on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- Admins may only change role / active. Nobody (admins included) can change their own access, so the last admin cannot lock themselves out.
create or replace function public.guard_profile() returns trigger language plpgsql set search_path = public as $$
begin
  if new.id <> old.id or new.email is distinct from old.email or new.created_at <> old.created_at then
    raise exception 'NOT_ALLOWED'; end if;
  if old.id = auth.uid() and (new.role <> old.role or new.active <> old.active) then
    raise exception 'NOT_ALLOWED'; end if;
  return new;
end $$;
drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before update on public.profiles for each row execute function public.guard_profile();

-- Drafts: approved staff only, own row only, and a size cap so a draft cannot be used as free storage.
drop policy if exists "own draft only" on public.drafts;
create policy "own draft only" on public.drafts for all to authenticated
  using (uid = auth.uid() and public.is_staff())
  with check (uid = auth.uid() and public.is_staff() and length(j) <= 200000);


-- ======================= 2. Lock down records and recycle bin =======================
drop policy if exists "staff use records" on public.records;
drop policy if exists "staff read records" on public.records;
drop policy if exists "staff add records" on public.records;
drop policy if exists "staff edit records" on public.records;
drop policy if exists "admin delete records" on public.records;
drop policy if exists "staff use recycle bin" on public.recycle_bin;
drop policy if exists "admin recycle bin" on public.recycle_bin;

-- RLS stays enabled with no policies, and table privileges are removed.
revoke all on public.records, public.recycle_bin from anon, authenticated;
revoke all on public.drafts, public.profiles from anon;
revoke truncate, references, trigger on public.drafts, public.profiles from authenticated;
-- Profiles: signed-in users can never insert or delete rows, and can update only role/active (RLS + trigger above limit that to admins).
revoke insert, delete, update on public.profiles from authenticated;
grant update (role, active) on public.profiles to authenticated;

-- Audit trail: who last wrote each record, and when.
alter table public.records add column if not exists updated_by uuid, add column if not exists updated_at timestamptz;
create or replace function public.stamp_record() returns trigger language plpgsql set search_path = public as
$$ begin new.updated_by := auth.uid(); new.updated_at := now(); return new; end $$;
drop trigger if exists records_stamp on public.records;
create trigger records_stamp before insert or update on public.records
  for each row execute function public.stamp_record();

-- Access log: which account viewed / added / edited which property, and when (kept 180 days).
create table if not exists public.access_log (
  id bigserial primary key, uid uuid not null, action text not null, ref text, at timestamptz not null default now());
create index if not exists access_log_by_user on public.access_log (uid, action, at);
create index if not exists access_log_by_ref  on public.access_log (ref, uid, at);
alter table public.access_log enable row level security;
revoke all on public.access_log from anon, authenticated;

-- Previous versions: every update or delete of a record keeps the old copy, so nobody can quietly rewrite history
-- (the change log stored inside a record can be edited by whoever saves it; this table cannot).
create table if not exists public.record_audit (
  id bigserial primary key, k text not null, action text not null, old_j text, by_uid uuid, at timestamptz not null default now());
create index if not exists record_audit_by_key on public.record_audit (k, at desc);
alter table public.record_audit enable row level security;
revoke all on public.record_audit from anon, authenticated;

create or replace function public.audit_record() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' then
    if old.j is distinct from new.j then
      insert into public.record_audit (k, action, old_j, by_uid) values (old.k, 'update', old.j, auth.uid()); end if;
    return new;
  end if;
  insert into public.record_audit (k, action, old_j, by_uid) values (old.k, 'delete', old.j, auth.uid());
  return old;
end $$;
drop trigger if exists records_audit on public.records;
create trigger records_audit after update or delete on public.records
  for each row execute function public.audit_record();

-- Admin only: paged full reads, recycle bin writes, deletes, clear.
create or replace function public.admin_list(p_store text, p_from int, p_n int default 1000)
returns table (k text, j text) language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  if p_store = 'records' then
    return query select r.k, r.j from public.records r order by r.k offset p_from limit least(p_n, 1000);
  elsif p_store = 'recycle_bin' then
    return query select r.k, r.j from public.recycle_bin r order by r.k offset p_from limit least(p_n, 1000);
  else raise exception 'BAD_STORE'; end if;
end $$;

create or replace function public.admin_put_bin(p_rows jsonb) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  if p_rows is null or jsonb_typeof(p_rows) <> 'array' then raise exception 'INVALID: bad request'; end if;
  insert into public.recycle_bin (k, j) select x->>'k', x->>'j' from jsonb_array_elements(p_rows) x
  on conflict (k) do update set j = excluded.j;
end $$;

create or replace function public.admin_delete(p_store text, p_keys text[]) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  if p_store = 'records' then delete from public.records where k = any(p_keys);
  elsif p_store = 'recycle_bin' then delete from public.recycle_bin where k = any(p_keys);
  else raise exception 'BAD_STORE'; end if;
end $$;

create or replace function public.admin_clear(p_store text) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  if p_store = 'records' then delete from public.records where true;
  elsif p_store = 'recycle_bin' then delete from public.recycle_bin where true;
  else raise exception 'BAD_STORE'; end if;
end $$;


-- ======================= 3. Rate limits, validation, saves and reports =======================
-- ---------- Rate limiting ----------
create table if not exists public.api_log (
  id bigserial primary key, uid uuid not null, kind text not null, at timestamptz not null default now());
create index if not exists api_log_lookup on public.api_log (uid, kind, at);
alter table public.api_log enable row level security;
revoke all on public.api_log from anon, authenticated;

create or replace function public.rate_check(p_kind text, p_max int, p_window interval) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if random() < 0.02 then
    delete from public.api_log where at < now() - interval '1 day';
    delete from public.access_log where at < now() - interval '180 days';
  end if;
  if (select count(*) from public.api_log where uid = auth.uid() and kind = p_kind and at > now() - p_window) >= p_max
    then raise exception 'RATE_LIMITED'; end if;
  insert into public.api_log (uid, kind) values (auth.uid(), p_kind);
end $$;

create or replace function public.session_ok() returns boolean
language sql stable security definer set search_path = public as $$ select public.is_staff() $$;

-- Staff limits: 30 lookups/minute, 15 "not found" lookups per 10 minutes (stops ID guessing) and 500 property views per day
-- (stops bulk copying). Admins are exempt. The lookup must name ONE property (ulb~ward~gis id): partial keys are refused,
-- so it cannot be used to list a ward or a whole ULB.
create or replace function public.get_record(p_base text) returns setof text
language plpgsql volatile security definer set search_path = public as $$
declare adm boolean := public.is_admin(); rw record; n int := 0;
begin
  if not public.is_staff() then raise exception 'NOT_ALLOWED'; end if;
  if p_base is null or length(p_base) > 300 or p_base !~ '^[a-z0-9_]+~[^~]+~[^~]+$'
    then raise exception 'INVALID: enter both Ward and GIS ID to look up a property'; end if;
  if not adm then
    if (select count(*) from public.api_log where uid = auth.uid() and kind = 'miss' and at > now() - interval '10 minutes') >= 15
      then raise exception 'RATE_LIMITED'; end if;
    if (select count(*) from public.access_log where uid = auth.uid() and action = 'view' and at > now() - interval '1 day') >= 500
      then raise exception 'RATE_LIMITED_DAILY'; end if;
    perform public.rate_check('lookup', 30, interval '1 minute');
  end if;
  for rw in select r.k, r.j from public.records r
            where starts_with(r.k, p_base || '~') and substring(r.k from length(p_base) + 2) ~ '^[0-9]+$'
            order by r.k limit 5 loop
    n := n + 1;
    insert into public.access_log (uid, action, ref) values (auth.uid(), 'view', rw.k);
    return next rw.j;
  end loop;
  if n = 0 then
    insert into public.access_log (uid, action, ref) values (auth.uid(), 'miss', p_base);
    if not adm then insert into public.api_log (uid, kind) values (auth.uid(), 'miss'); end if;
  end if;
end $$;

-- ---------- Validation (mirrors the form rules; the browser keeps only friendly hints) ----------
create or replace function public.blank_or_na(v text) returns boolean language sql immutable set search_path = public as
$$ select v is null or lower(btrim(v)) in ('', 'na', 'n/a', '0') $$;

-- A text value is fine if it is at most 500 characters and has no control characters (tabs and line breaks are allowed).
create or replace function public.text_ok(v jsonb) returns boolean language sql immutable set search_path = public as $$
  select jsonb_typeof(v) <> 'string' or (length(v #>> '{}') <= 500 and (v #>> '{}') !~ '[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]') $$;

-- Identifier hygiene: Ward / GIS ID are used to build record keys and are shown all over the UI, so they may not contain
-- characters that can break out of HTML or JavaScript contexts (< > " ' ` \ &) or the key separator (~).
create or replace function public.id_chars_ok(v text) returns boolean language sql immutable set search_path = public as
$$ select v is null or (v !~ '[<>"''`\\&~]' and length(v) <= 100) $$;

-- Same normalisation the app uses when it builds a key: trim, lower-case, runs of "/" or whitespace become "_".
create or replace function public.norm_id(v text) returns text language sql immutable set search_path = public as
$$ select regexp_replace(regexp_replace(lower(coalesce(v, '')), '^\s+|\s+$', '', 'g'), '[/\s]+', '_', 'g') $$;

-- The key a record MUST be stored under: ulb~ward~gis (the ~n counter is added by the app).
create or replace function public.record_key_base(r jsonb) returns text language sql immutable set search_path = public as
$$ select coalesce(nullif(r->>'ulb_file', ''), 'mcpaonta') || '~' || public.norm_id(r->>'ward') || '~' || public.norm_id(r->>'gis_id') $$;

create or replace function public.validate_record(r jsonb) returns void language plpgsql immutable set search_path = public as $$
declare f record; e jsonb; t record; mx int; u text := coalesce(nullif(r->>'ulb_file', ''), 'mcpaonta');
begin
  if r is null or jsonb_typeof(r) <> 'object' then raise exception 'INVALID: record is malformed'; end if;
  for t in select key, value from jsonb_each(r) loop
    if not public.text_ok(t.value) then raise exception 'INVALID: % is too long or has unsupported characters', t.key; end if;
  end loop;
  if position('~' in coalesce(r->>'gis_id','')) > 0 or position('~' in coalesce(r->>'ward','')) > 0
    then raise exception 'INVALID: Ward and GIS ID cannot contain the ~ character'; end if;
  if not public.id_chars_ok(r->>'ward') or not public.id_chars_ok(r->>'gis_id')
    then raise exception 'INVALID: Ward and GIS ID cannot contain < > " '' ` \ & or be longer than 100 characters'; end if;
  if btrim(coalesce(r->>'ward','')) = '' then raise exception 'INVALID: Ward is required'; end if;
  if btrim(coalesce(r->>'gis_id','')) = '' then raise exception 'INVALID: GIS ID is required'; end if;
  mx := case u when 'mcpaonta' then 13 when 'mcnahan' then 13 when 'npbhota' then 7 end;
  if mx is null then raise exception 'INVALID: unknown ULB'; end if;
  if r->>'ward' !~ '^Ward [1-9][0-9]*$' or substring(r->>'ward' from 6)::int > mx then raise exception 'INVALID: Ward is not valid for this ULB'; end if;
  if btrim(coalesce(r->>'mobile_no','')) <> '' and btrim(r->>'mobile_no') !~ '^([0-9]{10}|\+[1-9][0-9]{6,14})$'
    then raise exception 'INVALID: mobile number must be 10 digits or + country code and number'; end if;
  if not public.blank_or_na(r->>'open_plot_area') and btrim(r->>'open_plot_area') !~ '^([0-9]+(\.[0-9]+)?|\.[0-9]+)$'
    then raise exception 'INVALID: plot area must be a plain number'; end if;
  for f in select value from jsonb_each(coalesce(r->'floors', '{}'::jsonb)) loop
    if jsonb_typeof(f.value) <> 'array' then raise exception 'INVALID: floors are malformed'; end if;
    for e in select * from jsonb_array_elements(f.value) loop
      if jsonb_typeof(e) <> 'object' then raise exception 'INVALID: floors are malformed'; end if;
      for t in select key, value from jsonb_each(e) loop
        if not public.text_ok(t.value) then raise exception 'INVALID: floor % is too long or has unsupported characters', t.key; end if;
      end loop;
      if not public.blank_or_na(e->>'area') and (btrim(e->>'area') !~ '^([0-9]+(\.[0-9]+)?|\.[0-9]+)$' or btrim(e->>'area')::numeric <= 0)
        then raise exception 'INVALID: floor area must be a positive number'; end if;
    end loop;
  end loop;
end $$;

-- Duplicates: the record key is ULB~ward~GIS ID (normalised), so 'insert' of an existing property fails with RECORD_EXISTS.
-- Modes: insert / update (staff + admin, validated), upsert (admin, validated), bulk (admin, imports, not validated).
-- Staff can only 'update' a property they viewed or added in the last 24 hours (LOAD_FIRST otherwise), at most 20 rows per call.
create or replace function public.write_records(p_rows jsonb) returns void
language plpgsql volatile security definer set search_path = public as $$
declare r jsonb; m text; rk text; kb text; adm boolean := public.is_admin();
begin
  if not public.is_staff() then raise exception 'NOT_ALLOWED'; end if;
  if p_rows is null or jsonb_typeof(p_rows) <> 'array' then raise exception 'INVALID: bad request'; end if;
  if not adm then perform public.rate_check('write', 60, interval '1 minute'); end if;
  if jsonb_array_length(p_rows) > 1000 or (not adm and jsonb_array_length(p_rows) > 20) then raise exception 'TOO_MANY'; end if;
  for r in select * from jsonb_array_elements(p_rows) loop
    m := r->>'mode'; rk := r->>'k';
    if rk is null or r->>'j' is null or length(rk) > 1500 or length(r->>'j') > 500000 then raise exception 'TOO_LARGE'; end if;
    if ((r->>'j')::jsonb)->>'id' is distinct from rk then raise exception 'INVALID: record key does not match'; end if;
    if m is distinct from 'bulk' then
      if rk !~ '^[a-z0-9_]+~[^~]+~[^~]+~[0-9]+$' then raise exception 'INVALID: record key is malformed'; end if;
      perform public.validate_record(((r->>'j')::jsonb)->'r');
      -- the key must be the one derived from the record's own ULB / Ward / GIS ID (no storing one property under another's key)
      kb := public.record_key_base(((r->>'j')::jsonb)->'r');
      if not starts_with(rk, kb || '~') or substring(rk from length(kb) + 2) !~ '^[0-9]+$'
        then raise exception 'INVALID: record key does not match its Ward / GIS ID'; end if;
    else
      -- imports skip the form rules, but never the identifier hygiene
      if not public.id_chars_ok(((r->>'j')::jsonb)->'r'->>'ward') or not public.id_chars_ok(((r->>'j')::jsonb)->'r'->>'gis_id')
        then raise exception 'INVALID: Ward and GIS ID contain unsupported characters'; end if;
    end if;
    if m = 'insert' then
      begin
        insert into public.records (k, j) values (rk, r->>'j');
      exception when unique_violation then raise exception 'RECORD_EXISTS';
      end;
      insert into public.access_log (uid, action, ref) values (auth.uid(), 'insert', rk);
    elsif m = 'update' then
      if not adm and not exists (select 1 from public.access_log a where a.uid = auth.uid() and a.ref = rk
                                   and a.action in ('view', 'insert') and a.at > now() - interval '24 hours')
        then raise exception 'LOAD_FIRST'; end if;
      update public.records set j = r->>'j' where public.records.k = rk;
      if not found then raise exception 'RECORD_MISSING'; end if;
      insert into public.access_log (uid, action, ref) values (auth.uid(), 'update', rk);
    elsif m in ('upsert', 'bulk') and adm then
      insert into public.records (k, j) values (rk, r->>'j') on conflict (k) do update set j = excluded.j;
    else
      raise exception 'NOT_ALLOWED';
    end if;
  end loop;
end $$;

-- ---------- Reports (admin only): ward summary, occupancy, pending remarks, property category, data health ----------
create or replace function public.occ_category(o text) returns text language sql immutable set search_path = public as $$
  select case
    when upper(btrim(coalesce(o,''))) like '%SELF%' or upper(btrim(coalesce(o,''))) like '%LETOUT%' or upper(btrim(coalesce(o,''))) like '%LET OUT%' then 'residential'
    when btrim(coalesce(o,'')) = '' or upper(btrim(o)) in ('N/A','UNDER CONSTRUCTION','CATTLE SHED','OTHERS','PUBLIC WORSHIP','BURIAL & CREMATION') then 'others'
    else 'commercial' end $$;

create or replace function public.floor_has_data(e jsonb) returns boolean language sql immutable set search_path = public as $$
  select case
    when e is null or jsonb_typeof(e) <> 'array' or jsonb_array_length(e) = 0 then false
    when jsonb_array_length(e) > 1 then true
    else exists (select 1 from jsonb_array_elements(e) x where
      lower(btrim(coalesce(x->>'yes_no',''))) = 'yes'
      or (case when btrim(coalesce(x->>'area','')) ~ '^([0-9]+(\.[0-9]+)?|\.[0-9]+)$' then btrim(x->>'area')::numeric > 0 else false end)
      or not public.blank_or_na(x->>'zone') or not public.blank_or_na(x->>'building_type')
      or not public.blank_or_na(x->>'year') or not public.blank_or_na(x->>'occupancy')
      or not public.blank_or_na(x->>'remarks')) end $$;

create or replace function public.admin_reports(p_ulb text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  return (
  with recs as (
    select row_number() over () as rid, (x.j::jsonb)->'r' as r from public.records x
    where coalesce(((x.j::jsonb)->'r')->>'ulb_file', 'mcpaonta') = p_ulb
  ),
  ents as (
    select rc.rid, e from recs rc
    cross join lateral jsonb_each(coalesce(rc.r->'floors', '{}'::jsonb)) f
    cross join lateral jsonb_array_elements(case when jsonb_typeof(f.value) = 'array' then f.value else '[]'::jsonb end) e
  ),
  yes as (select rid, e->>'occupancy' as occ from ents where lower(btrim(coalesce(e->>'yes_no',''))) = 'yes'),
  wards as (select coalesce(nullif(btrim(r->>'ward'),''),'Unassigned') as ward, count(*)::int as count from recs group by 1),
  occs as (select case when public.blank_or_na(occ) then 'N/A' else occ end as occupancy, count(*)::int as count from yes group by 1),
  pend as (select r->>'ward' as ward, r->>'gis_id' as gis_id, r->>'owner_name' as owner_name, r->>'mobile_no' as mobile_no, r->>'remarks' as remarks
           from recs where not public.blank_or_na(r->>'remarks')),
  catn as (select rid, public.occ_category(occ) as cat, count(*)::int as n from yes group by 1, 2),
  catr as (select rc.rid, rc.r, jsonb_object_agg(c.cat, jsonb_build_object('entries', c.n)) as cats
           from recs rc join catn c using (rid) group by rc.rid, rc.r),
  mob as (select btrim(r->>'mobile_no') as m, count(distinct regexp_replace(lower(btrim(r->>'owner_name')), '\s+', ' ', 'g')) as owners
          from recs where btrim(coalesce(r->>'mobile_no','')) ~ '^([0-9]{10}|\+[1-9][0-9]{6,14})$' and btrim(coalesce(r->>'owner_name','')) <> '' group by 1),
  dups as (select lower(btrim(r->>'ward')) as w, lower(btrim(r->>'gis_id')) as g, count(*)::int as n
           from recs where btrim(coalesce(r->>'gis_id','')) <> '' group by 1, 2),
  health as (
    select rc.r, coalesce(d.n, 0) as dup, array_remove(array[
      case when public.blank_or_na(rc.r->>'owner_name') then 'no_owner' end,
      case when public.blank_or_na(rc.r->>'mobile_no') then 'no_mobile' end,
      case when not public.blank_or_na(rc.r->>'mobile_no') and btrim(rc.r->>'mobile_no') !~ '^([0-9]{10}|\+[1-9][0-9]{6,14})$' then 'bad_mobile' end,
      case when btrim(coalesce(rc.r->>'mobile_no','')) ~ '^([0-9]{10}|\+[1-9][0-9]{6,14})$' and coalesce(mb.owners, 0) > 1 then 'shared_mobile' end,
      case when public.blank_or_na(rc.r->>'open_plot_area')
             and not exists (select 1 from jsonb_each(coalesce(rc.r->'floors', '{}'::jsonb)) f where public.floor_has_data(f.value)) then 'no_data' end,
      case when coalesce(d.n, 0) > 1 then 'duplicate_id' end], null) as issues
    from recs rc
    left join mob mb on mb.m = btrim(rc.r->>'mobile_no')
    left join dups d on d.w = lower(btrim(rc.r->>'ward')) and d.g = lower(btrim(rc.r->>'gis_id'))
  )
  select jsonb_build_object(
    'total', (select count(*) from recs),
    'wardStats', coalesce((select jsonb_agg(to_jsonb(w)) from wards w), '[]'::jsonb),
    'occStats', coalesce((select jsonb_agg(to_jsonb(o)) from occs o), '[]'::jsonb),
    'pending', coalesce((select jsonb_agg(to_jsonb(p)) from pend p), '[]'::jsonb),
    'category', jsonb_build_object(
      'none', (select count(*) from recs) - (select count(*) from catr),
      'rows', coalesce((select jsonb_agg(jsonb_build_object(
        'ward', r->>'ward', 'gis_id', r->>'gis_id', 'old_house_no', r->>'old_house_no', 'owner_name', r->>'owner_name',
        'father_husband_name', r->>'father_husband_name', 'mobile_no', r->>'mobile_no', 'cats', cats,
        'keys', (select jsonb_agg(k) from jsonb_object_keys(cats) k),
        'mixed', (cats ? 'residential' and cats ? 'commercial'), 'rec', jsonb_build_object('ulb_file', p_ulb))) from catr), '[]'::jsonb)),
    'health', coalesce((select jsonb_agg(jsonb_build_object(
        'ward', r->>'ward', 'gis_id', r->>'gis_id', 'owner_name', r->>'owner_name', 'mobile_no', r->>'mobile_no',
        'issues', to_jsonb(issues), 'dup', dup, 'rec', jsonb_build_object('ulb_file', p_ulb))) from health where cardinality(issues) > 0), '[]'::jsonb)
  ));
end $$;


-- Admin only: the latest access events (who viewed / added / edited which property).
create or replace function public.admin_access_log(p_n int default 300)
returns table (logged_at timestamptz, email text, action text, ref text)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'NOT_ALLOWED'; end if;
  return query select a.at, p.email, a.action, a.ref
    from public.access_log a left join public.profiles p on p.id = a.uid
    order by a.at desc limit least(p_n, 500);
end $$;


-- ======================= 4. Permissions =======================
-- Supabase gives every new function EXECUTE for anon + authenticated by default, and functions get PUBLIC execute
-- unless it is revoked. So: start by taking everything away, then grant back only what the app really calls.

-- (a) Internal functions: never callable through /rest/v1/rpc by anyone. They still work, because the
--     security-definer RPCs below run as the function owner, and triggers do not check EXECUTE when they fire.
revoke execute on function
  public.rate_check(text, int, interval),
  public.handle_new_user(), public.guard_profile(), public.stamp_record(), public.audit_record(),
  public.blank_or_na(text), public.text_ok(jsonb), public.validate_record(jsonb),
  public.occ_category(text), public.floor_has_data(jsonb),
  public.id_chars_ok(text), public.norm_id(text), public.record_key_base(jsonb)
from public, anon, authenticated;

-- Supabase's own "auto-enable RLS" event-trigger helper (present only if that project setting is on).
-- Only the event trigger calls it, and event triggers do not check EXECUTE, so it can be closed to the API.
do $$ begin
  if to_regprocedure('public.rls_auto_enable()') is not null then
    revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
  end if;
end $$;

-- (b) Role helpers: RLS policies call them as the signed-in user, so authenticated needs EXECUTE. They only ever
--     answer about the caller's own account. Signed-out visitors get nothing.
revoke execute on function public.is_staff(), public.is_admin() from public, anon;
grant  execute on function public.is_staff(), public.is_admin() to authenticated;

-- (c) The RPCs index.html calls. Signed-in only; each one checks is_staff() / is_admin() itself, so an
--     unapproved or disabled account gets NOT_ALLOWED. (This is the "authenticated can execute a SECURITY DEFINER
--     function" advisor warning: it is intended here. SECURITY INVOKER would not work because records and
--     recycle_bin have no direct table access on purpose.)
revoke execute on function public.session_ok(), public.get_record(text), public.write_records(jsonb),
  public.admin_list(text, int, int), public.admin_put_bin(jsonb), public.admin_delete(text, text[]),
  public.admin_clear(text), public.admin_reports(text), public.admin_access_log(int) from public, anon;
grant execute on function public.session_ok(), public.get_record(text), public.write_records(jsonb),
  public.admin_list(text, int, int), public.admin_put_bin(jsonb), public.admin_delete(text, text[]),
  public.admin_clear(text), public.admin_reports(text), public.admin_access_log(int) to authenticated;

-- (d) Future functions created here are not callable by signed-out visitors unless you grant it.
alter default privileges in schema public revoke execute on functions from anon;

-- (e) The bigserial sequences behind the log tables are only used inside the definer functions.
revoke all on all sequences in schema public from anon, authenticated;

-- ---------- Check the result (optional): anon_can_run must be false everywhere ----------
-- select p.proname, p.prosecdef as definer, has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can_run,
--        has_function_privilege('authenticated', p.oid, 'EXECUTE') as signed_in_can_run
-- from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' order by 1;

-- ======================= 5. Explicit "no direct access" policies =======================
-- These tables are only ever touched by the security-definer functions above (the function owner bypasses RLS).
-- With RLS on and no policy, access is already denied, but the Supabase advisor reports that as "RLS enabled, no policy".
-- A deny-all policy states the intent, silences the warning, and keeps them closed even if a table grant is ever added by mistake.
do $$
declare t text;
begin
  foreach t in array array['records', 'recycle_bin', 'access_log', 'record_audit', 'api_log']
  loop
    execute format('drop policy if exists "no direct access" on public.%I', t);
    execute format('create policy "no direct access" on public.%I for all to anon, authenticated using (false) with check (false)', t);
  end loop;
end $$;

-- Catch-all: any OTHER table in public that has RLS on but still no policy (e.g. left over from an earlier script)
-- gets the same deny-all policy. It changes nothing functionally (no policy already meant no access); it only
-- makes the intent explicit. If one of those tables should be usable from the app, replace its policy with a real one.
do $$
declare t record;
begin
  for t in
    select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p') and c.relrowsecurity
      and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
  loop
    execute format('create policy "no direct access" on public.%I for all to anon, authenticated using (false) with check (false)', t.relname);
    raise notice 'Added deny-all policy to public.%', t.relname;
  end loop;
end $$;

-- Policies that do let people in (already created in section 1):
--   profiles : select own row (admins: all rows); update role/active by admins only; no insert / delete
--   drafts   : approved staff, own row only, draft size capped

-- Check (optional): every table should show at least one policy.
-- select tablename, policyname, cmd, roles, qual, with_check from pg_policies where schemaname = 'public' order by 1, 2;

-- ---------- Make yourself the first admin (sign up in the app first, then change the email and run) ----------
-- (Run it in the SQL Editor; the guard trigger lets the dashboard do this because it is not a signed-in app user.)
-- update public.profiles set role = 'admin', active = true where email = 'you@example.com';
