-- =============================================================================
-- xbase storage.objects policies (idempotent).
--
-- Convention: object names start with the workspace id —
--     <workspace_uuid>/<anything>          e.g. 7c9e.../avatars/me.png
-- and buckets are named <APP_ID>-<name> (the Rust backend does this for you).
--
--   read    : any workspace member (owner/admin/member/viewer)
--   write   : owner/admin/member           (insert, update, delete)
--
-- `storage.objects` is owned by supabase_storage_admin, so a plain `postgres`
-- session may not be allowed to create policies on it. migrations/0005 tries
-- and skips with a NOTICE if it lacks the privilege; this file is the same SQL
-- for running as the superuser instead:
--
--     ./scripts/apply-storage-policies.sh
-- =============================================================================

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
end
$$;
