-- Test of 462, batch 2/3 (24 users). No lasting changes: compares old vs new offices RLS, then ROLLBACK.
-- Paste into the Supabase SQL editor. Good result: missing = 0 and extra = 0 on every row.
begin;
create temp table _t(uid uuid, phase text, ids uuid[], ms numeric) on commit drop;

do $do$
declare u uuid; t0 timestamptz; a uuid[]; ms numeric;
begin
  foreach u in array array['a1251ae8-974b-473b-b518-16c8c39b19a5','f7e993b9-a44a-4aee-816e-7bd186b62e31','555f0b45-adc8-42c3-81dc-b0122905a240','93b402dc-fe8c-4cf6-bd8f-6d8ee399a773','b80908aa-34b1-4164-8886-5e5fa952cbd3','6288bbec-5e95-409e-ae28-a03d08cf852b','0be34a88-6acd-46ec-8237-88617b8173cd','10986b10-220d-4507-821f-b50fb6b21e3a','8c7800ef-f213-4bf4-85e8-c8b4c879d442','0520a9a6-640c-4209-8adb-701c07db0310','ccd508de-18e1-4803-8306-de4ff5a58a9c','79e9cf3a-57e3-472c-abf3-c2aad0749996','4e3afef1-1633-4de2-953f-ca7557549216','fd3c5298-f594-4739-adef-9aeda72f6045','74e0f699-79da-4d85-8004-a0af02a64a03','ee3a75a8-0a19-4529-a9a0-572eab07cd60','c6731d92-08aa-473b-89dd-908db6ad44aa','e99fd030-fa24-4572-83fa-87a63f5a4e5f','5c884f6d-6dce-4ed6-bac7-5df9296141ec','b02998f2-f0dd-4331-b2f7-afc6b1f0ae30','d7392a5d-d6cf-4b3d-a897-9ac78e0eaf8e','f44975e1-c858-48ca-b86a-7928a5a6ebeb','02e78aed-1973-40f0-b506-f5cca2e22301','3e2a6831-ba13-4a08-aa30-b7bde81f99ea']::uuid[] loop
    perform set_config('request.jwt.claims', coalesce(json_build_object('sub', u, 'role', 'authenticated')::text, '{"role":"anon"}'), true);
    perform set_config('role', case when u is null then 'anon' else 'authenticated' end, true);
    t0 := clock_timestamp();
    select coalesce(array_agg(o.id order by o.id), '{}') into a from public.offices o;
    ms := extract(epoch from clock_timestamp() - t0) * 1000;
    perform set_config('role', 'none', true);
    insert into _t values (u, 'old', a, ms);
  end loop;
end $do$;

-- 462: offices RLS in a single pass.
--
-- The six SELECT policies on public.offices each called a SECURITY DEFINER
-- function per row (can_access_office, user_has_office_access,
-- partner_serves_office, vault_legacy_can_read_office, legacy_office_in_office,
-- legacy_iv_in_office). With ~4.4k offices a non-admin office list took ~3s.
--
-- visible_office_ids() works out the caller's offices once per statement;
-- the policy probes it as a hashed subplan. Visibility is unchanged:
--   * any user_offices link            (user_has_office_access; also covers
--                                        legacy, legacy IV, legacy_office,
--                                        office_user/admin and eAssist own links)
--   * users.office_id for office_user, office_admin, legacy_office
--   * eAssist staff: offices of supervisees, one and two levels down
--   * partners: partner_leads, partner_client_assignments, unitas_active offices
--   * eassist_admin: everything
-- launch_offices_select and the ALL/UPDATE policies are untouched.

create or replace function public.offices_read_all()
returns boolean
language sql
stable security definer
set search_path to 'public'
as $$
  select coalesce(
    (select u.role = 'eassist_admin'::user_role from public.users u where u.id = auth.uid()),
    false)
$$;

create or replace function public.visible_office_ids()
returns setof uuid
language sql
stable security definer
set search_path to 'public'
as $$
  with me as (
    select u.id, u.role, u.office_id, u.partner_id
      from public.users u
     where u.id = auth.uid()
  )
  select uo.office_id
    from me join public.user_offices uo on uo.user_id = me.id
  union
  select me.office_id
    from me
   where me.office_id is not null
     and me.role::text in ('office_user', 'office_admin', 'legacy_office')
  union
  select uo.office_id
    from me
    join public.user_supervisors s on s.supervisor_id = me.id
    join public.user_offices uo on uo.user_id = s.supervisee_id
   where me.role::text = any(public.vault_staff_roles())
  union
  select uo.office_id
    from me
    join public.user_supervisors s1 on s1.supervisor_id = me.id
    join public.user_supervisors s2 on s2.supervisor_id = s1.supervisee_id
    join public.user_offices uo on uo.user_id = s2.supervisee_id
   where me.role::text = any(public.vault_staff_roles())
  union
  select pl.office_id
    from me join public.partner_leads pl on pl.partner_id = me.partner_id
  union
  select a.office_id
    from me join public.partner_client_assignments a on a.partner_id = me.partner_id
$$;

drop policy if exists "office user reads own office" on public.offices;
drop policy if exists offices_legacy_iv_select on public.offices;
drop policy if exists offices_legacy_office_read on public.offices;
drop policy if exists offices_legacy_read on public.offices;
drop policy if exists offices_partner_read on public.offices;
drop policy if exists offices_select on public.offices;

create policy offices_read on public.offices
  for select to public
  using (
    (select public.offices_read_all())
    or id in (select public.visible_office_ids())
    or (unitas_active is true and (select public.current_user_partner_id()) is not null)
  );

analyze public.offices, public.user_supervisors;


do $do$
declare u uuid; t0 timestamptz; a uuid[]; ms numeric;
begin
  foreach u in array array['a1251ae8-974b-473b-b518-16c8c39b19a5','f7e993b9-a44a-4aee-816e-7bd186b62e31','555f0b45-adc8-42c3-81dc-b0122905a240','93b402dc-fe8c-4cf6-bd8f-6d8ee399a773','b80908aa-34b1-4164-8886-5e5fa952cbd3','6288bbec-5e95-409e-ae28-a03d08cf852b','0be34a88-6acd-46ec-8237-88617b8173cd','10986b10-220d-4507-821f-b50fb6b21e3a','8c7800ef-f213-4bf4-85e8-c8b4c879d442','0520a9a6-640c-4209-8adb-701c07db0310','ccd508de-18e1-4803-8306-de4ff5a58a9c','79e9cf3a-57e3-472c-abf3-c2aad0749996','4e3afef1-1633-4de2-953f-ca7557549216','fd3c5298-f594-4739-adef-9aeda72f6045','74e0f699-79da-4d85-8004-a0af02a64a03','ee3a75a8-0a19-4529-a9a0-572eab07cd60','c6731d92-08aa-473b-89dd-908db6ad44aa','e99fd030-fa24-4572-83fa-87a63f5a4e5f','5c884f6d-6dce-4ed6-bac7-5df9296141ec','b02998f2-f0dd-4331-b2f7-afc6b1f0ae30','d7392a5d-d6cf-4b3d-a897-9ac78e0eaf8e','f44975e1-c858-48ca-b86a-7928a5a6ebeb','02e78aed-1973-40f0-b506-f5cca2e22301','3e2a6831-ba13-4a08-aa30-b7bde81f99ea']::uuid[] loop
    perform set_config('request.jwt.claims', coalesce(json_build_object('sub', u, 'role', 'authenticated')::text, '{"role":"anon"}'), true);
    perform set_config('role', case when u is null then 'anon' else 'authenticated' end, true);
    t0 := clock_timestamp();
    select coalesce(array_agg(o.id order by o.id), '{}') into a from public.offices o;
    ms := extract(epoch from clock_timestamp() - t0) * 1000;
    perform set_config('role', 'none', true);
    insert into _t values (u, 'new', a, ms);
  end loop;
end $do$;

select coalesce(u.role::text,'anon') role, o.uid, cardinality(o.ids) old_n, cardinality(n.ids) new_n,
  (select count(*) from unnest(o.ids) x where x <> all(n.ids)) missing,
  (select count(*) from unnest(n.ids) x where x <> all(o.ids)) extra,
  round(o.ms) old_ms, round(n.ms) new_ms
from _t o join _t n on n.uid is not distinct from o.uid and n.phase='new'
left join public.users u on u.id = o.uid
where o.phase='old' order by 1;
rollback;
