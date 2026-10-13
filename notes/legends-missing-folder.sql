-- Legends Family Dental (az.glendale.ford): find Sandra's missing Oct 1 folder.
-- READ-ONLY. Paste into the Supabase SQL editor. Run 2 and 5 first.

-- 1. Office row(s) and aliases (one row with empty slug_aliases = no duplicate)
select id, slug, slug_aliases, name, hub_office_id, active, created_at
from public.offices
where slug = 'az.glendale.ford' or 'az.glendale.ford' = any(slug_aliases) or name ilike 'legends family dental%';

-- 2. Folders at the office made Sep 28 - Oct 10 or updated since Oct 1, incl. hidden/trashed
select f.id, f.name, f.parent_id, p.name as parent_name, f.internal_only, f.deleted_at,
       f.created_at, f.updated_at, u.email as created_by
from public.document_folders f
join public.offices o on o.id = f.office_id
left join public.document_folders p on p.id = f.parent_id
left join public.users u on u.id = f.created_by
where o.slug = 'az.glendale.ford'
  and (f.created_at between '2026-09-28' and '2026-10-10' or f.updated_at >= '2026-10-01')
order by f.created_at;

-- 3. Folders Sandra made at ANY office (multi-location / changed profile)
select f.id, f.name, o.slug, o.name as office, f.internal_only, f.deleted_at, f.created_at, f.updated_at
from public.document_folders f
join public.users u on u.id = f.created_by
left join public.offices o on o.id = f.office_id
where u.full_name ilike 'sandra%' and f.created_at between '2026-09-28' and '2026-10-10'
order by f.created_at;

-- 4. Sandra's profile and office links
select u.id, u.email, u.full_name, u.role, po.slug as primary_office, uo.office_id, o2.slug as linked_office
from public.users u
left join public.offices po on po.id = u.office_id
left join public.user_offices uo on uo.user_id = u.id
left join public.offices o2 on o2.id = uo.office_id
where u.full_name ilike 'sandra%';

-- 5. Files uploaded around Oct 1 with folder state (folder_office <> az.glendale.ford = orphaned)
select d.id, d.file_name, d.created_at, d.deleted_at as file_trashed, d.internal_only as file_hidden,
       f.name as folder, f.deleted_at as folder_trashed, f.internal_only as folder_hidden,
       fo.slug as folder_office, ub.email as uploaded_by
from public.office_documents d
join public.offices o on o.id = d.office_id
left join public.document_folders f on f.id = d.folder_id
left join public.offices fo on fo.id = f.office_id
left join public.users ub on ub.id = d.uploaded_by
where o.slug = 'az.glendale.ford' and d.created_at between '2026-09-28' and '2026-10-13'
order by d.created_at;

-- 6. Was the office ever merged or edited
select occurred_at, action, actor_email, changed_keys, before_data->>'slug' as before_slug
from public.audit_log
where table_name = 'offices' and (after_data->>'slug' = 'az.glendale.ford' or before_data->>'name' ilike 'legends family dental%')
order by occurred_at;

-- 7. Exact trash time of trashed folders (use deleted_at to search Vercel / Supabase API logs)
select f.id, f.name, f.deleted_at, f.updated_at, f.created_at, c.email as created_by
from public.document_folders f
join public.offices o on o.id = f.office_id
left join public.users c on c.id = f.created_by
where o.slug = 'az.glendale.ford' and f.deleted_at is not null
order by f.deleted_at;

-- 8. Everyone who could have trashed it (office users, linked users, admins)
select distinct u.email, u.full_name, u.role,
       case when u.office_id = o.id then 'primary office' when uo.user_id is not null then 'linked' else 'admin' end as access
from public.offices o
join public.users u on u.office_id = o.id
   or exists (select 1 from public.user_offices x where x.user_id = u.id and x.office_id = o.id)
   or u.role in ('eassist_admin', 'eassist_vera_quality_assistant')
left join public.user_offices uo on uo.user_id = u.id and uo.office_id = o.id
where o.slug = 'az.glendale.ford'
order by access, u.email;
