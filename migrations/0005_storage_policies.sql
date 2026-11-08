-- =============================================================================
-- 0005 — Storage access helpers + workspace-scoped storage.objects policies
--
-- Object naming convention:  <workspace_uuid>/<path>   in bucket <APP_ID>-<name>
-- Policy SQL is mirrored in docker/storage-policies.sql (run it as the DB
-- superuser via scripts/apply-storage-policies.sh if the DO block below prints
-- the "skipped" notice because `postgres` does not own storage.objects).
-- =============================================================================

-- First path segment as a workspace id, or NULL if it is not a UUID.
create or replace function xbase.storage_object_workspace(object_name text) returns uuid
language sql immutable parallel safe set search_path = '' as $$
    select case
        when split_part(object_name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        then split_part(object_name, '/', 1)::uuid
    end
$$;

-- True when the caller holds one of `p_roles` in the workspace named by the
-- object's first path segment AND the bucket belongs to that workspace's app
-- (buckets are named <app_slug>-<name>).
create or replace function xbase.can_access_storage_object(p_bucket text, p_name text, p_roles text[])
returns boolean language sql stable security definer set search_path = '' as $$
    select exists (
        select 1
          from xbase.workspaces w
         where w.id = xbase.storage_object_workspace(p_name)
           and starts_with(p_bucket, w.app_slug || '-')
           and xbase.has_workspace_role(w.id, p_roles)
    )
$$;

revoke all on function xbase.can_access_storage_object(text, text, text[]) from public, anon;
grant execute on function xbase.can_access_storage_object(text, text, text[]) to authenticated, service_role;
grant execute on function xbase.storage_object_workspace(text) to authenticated, service_role;

do $$
begin
    drop policy if exists "xbase workspace read"   on storage.objects;
    drop policy if exists "xbase workspace insert" on storage.objects;
    drop policy if exists "xbase workspace update" on storage.objects;
    drop policy if exists "xbase workspace delete" on storage.objects;

    create policy "xbase workspace read" on storage.objects for select to authenticated
        using (xbase.can_access_storage_object(bucket_id, name, array['owner', 'admin', 'member', 'viewer']));

    create policy "xbase workspace insert" on storage.objects for insert to authenticated
        with check (xbase.can_access_storage_object(bucket_id, name, array['owner', 'admin', 'member']));

    create policy "xbase workspace update" on storage.objects for update to authenticated
        using (xbase.can_access_storage_object(bucket_id, name, array['owner', 'admin', 'member']))
        with check (xbase.can_access_storage_object(bucket_id, name, array['owner', 'admin', 'member']));

    create policy "xbase workspace delete" on storage.objects for delete to authenticated
        using (xbase.can_access_storage_object(bucket_id, name, array['owner', 'admin', 'member']));
exception
    when insufficient_privilege or undefined_table or invalid_schema_name then
        raise notice 'xbase: skipped storage.objects policies (%). Run scripts/apply-storage-policies.sh as the superuser.', sqlerrm;
end
$$;
