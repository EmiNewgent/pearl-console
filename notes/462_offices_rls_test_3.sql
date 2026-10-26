-- Test of 462, batch 3/3 (23 users). No lasting changes: compares old vs new offices RLS, then ROLLBACK.
-- Paste into the Supabase SQL editor. Good result: missing = 0 and extra = 0 on every row.
begin;
create temp table _t(uid uuid, phase text, ids uuid[], ms numeric) on commit drop;

do $do$
declare u uuid; t0 timestamptz; a uuid[]; ms numeric;
begin
  foreach u in array array['f83b8564-935b-4fd7-a183-64a4e214b7a5','65671854-44f1-45aa-a554-318af547edf0','a26dc8e3-9f89-4d5d-bbb1-196f1cb234b3','63c8c5db-12bb-4ce1-8440-994a2a92b6d0','a40819ac-23f0-4458-b966-9e5dace3490d','c7c588d7-78ea-42d6-84b6-07ebe97d489c','c060983b-a36a-45db-98b8-cc0e4334d7cc','a86b6397-df32-4071-9d68-7548e8984e80','7d9c4574-f69b-4450-9c4b-4139f92079cf','78ba9a7c-cd84-416a-9593-e8ba50f84266','6294666a-af05-4cd0-a1c8-9daa17d86a7a','5663d92f-14e5-4962-b26e-dda53444ae09','fccd4e59-a0cc-48d9-ba62-744678b8b1a9','4f4e3b29-45dd-475c-9402-192f030fb845','47c1e4ae-7852-4c1d-bdf2-02f7b4baac50','36592093-2494-4e67-947d-58fe30aea17d','3171c0e7-b860-4d04-8130-765878dbf7bc','1b50e355-6efb-4735-9fe6-4b29662a8c7c','11b1d201-b881-418e-9211-f37af5e1c412','54d831a1-a9b1-472f-a5cc-cf3d3068300b','f65ee7cb-b33e-4dce-b594-253b95255175','ddd10731-1e31-4ceb-9c0b-0158e9328a3e','d20d9b45-ef66-48b1-b062-0add33e654c9']::uuid[] loop
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
  foreach u in array array['f83b8564-935b-4fd7-a183-64a4e214b7a5','65671854-44f1-45aa-a554-318af547edf0','a26dc8e3-9f89-4d5d-bbb1-196f1cb234b3','63c8c5db-12bb-4ce1-8440-994a2a92b6d0','a40819ac-23f0-4458-b966-9e5dace3490d','c7c588d7-78ea-42d6-84b6-07ebe97d489c','c060983b-a36a-45db-98b8-cc0e4334d7cc','a86b6397-df32-4071-9d68-7548e8984e80','7d9c4574-f69b-4450-9c4b-4139f92079cf','78ba9a7c-cd84-416a-9593-e8ba50f84266','6294666a-af05-4cd0-a1c8-9daa17d86a7a','5663d92f-14e5-4962-b26e-dda53444ae09','fccd4e59-a0cc-48d9-ba62-744678b8b1a9','4f4e3b29-45dd-475c-9402-192f030fb845','47c1e4ae-7852-4c1d-bdf2-02f7b4baac50','36592093-2494-4e67-947d-58fe30aea17d','3171c0e7-b860-4d04-8130-765878dbf7bc','1b50e355-6efb-4735-9fe6-4b29662a8c7c','11b1d201-b881-418e-9211-f37af5e1c412','54d831a1-a9b1-472f-a5cc-cf3d3068300b','f65ee7cb-b33e-4dce-b594-253b95255175','ddd10731-1e31-4ceb-9c0b-0158e9328a3e','d20d9b45-ef66-48b1-b062-0add33e654c9']::uuid[] loop
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
