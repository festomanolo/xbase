-- =============================================================================
-- 0006 — closes three platform gaps
--
--   1. Storage: a workspace of app `x` can no longer reach a bucket of app `x-1`
--      (bucket `x-1-files` starts with `x-`). The bucket must belong to the
--      LONGEST registered app slug that prefixes it.
--   2. Realtime cluster: messages larger than Postgres' NOTIFY limit (~8 KB) are
--      spilled into an UNLOGGED table and only their id is NOTIFYed.
--   3. REST via API keys: helpers that table policies can use to admit an API
--      key's workspace (the backend sets them per transaction for key requests).
-- =============================================================================

-- 1. Storage bucket ownership ---------------------------------------------------

-- The app that owns a bucket: the longest slug s with bucket = s || '-' || name.
create or replace function xbase.bucket_app(p_bucket text) returns text
language sql stable security definer set search_path = '' as $$
    select a.slug
      from xbase.apps a
     where starts_with(p_bucket, a.slug || '-')
     order by length(a.slug) desc
     limit 1
$$;

create or replace function xbase.can_access_storage_object(p_bucket text, p_name text, p_roles text[])
returns boolean language sql stable security definer set search_path = '' as $$
    select exists (
        select 1
          from xbase.workspaces w
         where w.id = xbase.storage_object_workspace(p_name)
           and w.app_slug = xbase.bucket_app(p_bucket)
           and xbase.has_workspace_role(w.id, p_roles)
    )
$$;

revoke all on function xbase.bucket_app(text) from public, anon;
grant execute on function xbase.bucket_app(text) to authenticated, service_role;

-- 2. Realtime cluster spill -------------------------------------------------------

create unlogged table if not exists xbase.realtime_spill (
    id         bigint generated always as identity primary key,
    app_id     text not null,
    body       text not null,
    created_at timestamptz not null default now()
);
create index if not exists realtime_spill_created_idx on xbase.realtime_spill (created_at);
alter table xbase.realtime_spill enable row level security; -- internal: no policies
revoke all on xbase.realtime_spill from anon, authenticated;

-- 3. API-key principals for table policies -----------------------------------------
--
-- For requests authenticated with an x-api-key (scope rest:read / rest:write) the
-- backend runs the REST query as role `authenticated` with no user id, and sets
-- these transaction-local settings. A table opts in with a policy such as
--
--   create policy "api key workspace" on public.todos for all to authenticated
--     using (workspace_id = xbase.request_workspace_id())
--     with check (workspace_id = xbase.request_workspace_id());
--
-- User requests always reset them to '' so a user can never look like a key.

create or replace function xbase.request_workspace_id() returns uuid
language sql stable set search_path = '' as $$
    select nullif(current_setting('xbase.key_workspace_id', true), '')::uuid
$$;

create or replace function xbase.request_api_key_id() returns uuid
language sql stable set search_path = '' as $$
    select nullif(current_setting('xbase.key_id', true), '')::uuid
$$;

create or replace function xbase.request_app_slug() returns text
language sql stable set search_path = '' as $$
    select nullif(current_setting('xbase.key_app_slug', true), '')
$$;

grant usage on schema xbase to authenticated;
grant execute on function xbase.request_workspace_id(), xbase.request_api_key_id(), xbase.request_app_slug()
    to authenticated, service_role;
