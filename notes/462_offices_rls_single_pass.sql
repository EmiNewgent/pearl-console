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
