-- Test of 462, batch 1/3 (24 users). No lasting changes: compares old vs new offices RLS, then ROLLBACK.
-- Paste into the Supabase SQL editor. Good result: missing = 0 and extra = 0 on every row.
begin;
create temp table _t(uid uuid, phase text, ids uuid[], ms numeric) on commit drop;

do $do$
declare u uuid; t0 timestamptz; a uuid[]; ms numeric;
begin
  foreach u in array array['754828a4-87fb-4761-8a22-9f7536130c13','afd66d1f-139b-4a3f-9315-8deb7833a8a5','f16eaaac-ea3c-4e42-82d9-fe80c21144a6','1a6886a4-ec49-4439-b165-cf45e09a6b77','cd3ac8be-9e80-4f25-a128-8fe2e95364cb','1f06790c-1b59-42f2-9cf8-1d391aa8a1cb','b069b311-9a0b-4c4f-8847-ca331f722244','e6235bb4-bb35-46dc-ab7a-a65814122295','711720b1-d287-4ffd-95f0-c4fc39539550','aca3652f-7a82-406e-b694-8924873cf788','07529fa1-d7ac-4c9f-888d-78da6ff3c3ce','13c7faa9-a516-4157-9514-bcfb3f3f064c','16701585-fbdc-4522-a480-d56b1f5b8b6f','21d8325d-a584-4792-b9eb-87ce1663e7bc','6f7a170e-11f3-47f5-b4df-0694973fc54f','774c5f3c-e8bf-4ecd-85be-8fb06a90a353','c12a03ef-b4b1-4dda-9f97-a1f1933f4a83','1e81eb81-9921-4791-b794-32f67b564677','25380c6d-c617-4203-89be-de5212012dbb','271479b3-3a60-4785-a5a1-8dd9c678e8f7','9308c8e3-8992-4280-83c5-62ec82caa7d5','282d3443-88e1-4e8d-beb2-de6fd4867260','cdd9602b-6c14-4df9-963c-cc2e5890ac66','7d8cdc21-ab7e-4632-8435-51b21e3771c0']::uuid[] loop
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
  foreach u in array array['754828a4-87fb-4761-8a22-9f7536130c13','afd66d1f-139b-4a3f-9315-8deb7833a8a5','f16eaaac-ea3c-4e42-82d9-fe80c21144a6','1a6886a4-ec49-4439-b165-cf45e09a6b77','cd3ac8be-9e80-4f25-a128-8fe2e95364cb','1f06790c-1b59-42f2-9cf8-1d391aa8a1cb','b069b311-9a0b-4c4f-8847-ca331f722244','e6235bb4-bb35-46dc-ab7a-a65814122295','711720b1-d287-4ffd-95f0-c4fc39539550','aca3652f-7a82-406e-b694-8924873cf788','07529fa1-d7ac-4c9f-888d-78da6ff3c3ce','13c7faa9-a516-4157-9514-bcfb3f3f064c','16701585-fbdc-4522-a480-d56b1f5b8b6f','21d8325d-a584-4792-b9eb-87ce1663e7bc','6f7a170e-11f3-47f5-b4df-0694973fc54f','774c5f3c-e8bf-4ecd-85be-8fb06a90a353','c12a03ef-b4b1-4dda-9f97-a1f1933f4a83','1e81eb81-9921-4791-b794-32f67b564677','25380c6d-c617-4203-89be-de5212012dbb','271479b3-3a60-4785-a5a1-8dd9c678e8f7','9308c8e3-8992-4280-83c5-62ec82caa7d5','282d3443-88e1-4e8d-beb2-de6fd4867260','cdd9602b-6c14-4df9-963c-cc2e5890ac66','7d8cdc21-ab7e-4632-8435-51b21e3771c0']::uuid[] loop
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
