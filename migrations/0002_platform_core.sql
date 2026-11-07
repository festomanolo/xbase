-- =============================================================================
-- xbase platform core: memberships, invitations, billing state, API keys,
-- webhook idempotency, background jobs, realtime change notifications and
-- full RLS policies.
--
-- Request traffic runs as the `authenticated` role with request.jwt.claims set
-- (see backend/src/rls.rs), so these policies are the authorization layer.
-- Internal tables (jobs, webhook_events) have RLS enabled with no policies:
-- only the backend's own connection role (table owner) can touch them.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Workspaces: billing + timestamps
-- ---------------------------------------------------------------------------
alter table xbase.workspaces
    add column if not exists updated_at              timestamptz not null default now(),
    add column if not exists billing_provider        text,
    add column if not exists billing_customer_id     text,
    add column if not exists billing_subscription_id text,
    add column if not exists subscription_status     text,
    add column if not exists current_period_end      timestamptz;

create index if not exists idx_workspaces_billing_sub
    on xbase.workspaces (billing_subscription_id) where billing_subscription_id is not null;
create index if not exists idx_workspaces_billing_customer
    on xbase.workspaces (billing_customer_id) where billing_customer_id is not null;

create or replace function xbase.touch_updated_at() returns trigger
language plpgsql as $$
begin
    new.updated_at := now();
    return new;
end $$;

drop trigger if exists trg_workspaces_touch on xbase.workspaces;
create trigger trg_workspaces_touch before update on xbase.workspaces
    for each row execute function xbase.touch_updated_at();

-- ---------------------------------------------------------------------------
-- 2. Memberships
-- ---------------------------------------------------------------------------
create table if not exists xbase.workspace_members (
    workspace_id uuid not null references xbase.workspaces(id) on delete cascade,
    user_id      uuid not null,
    role         text not null default 'member'
                 check (role in ('owner', 'admin', 'member', 'viewer')),
    created_at   timestamptz not null default now(),
    primary key (workspace_id, user_id)
);
create index if not exists idx_workspace_members_user on xbase.workspace_members (user_id);

-- Helpers are SECURITY DEFINER so policies on workspace_members can consult
-- workspace_members without infinite RLS recursion.
create or replace function xbase.workspace_role(ws uuid) returns text
language sql stable security definer set search_path = '' as $$
    select m.role from xbase.workspace_members m
     where m.workspace_id = ws and m.user_id = auth.uid()
$$;

create or replace function xbase.is_workspace_member(ws uuid) returns boolean
language sql stable security definer set search_path = '' as $$
    select xbase.workspace_role(ws) is not null
$$;

create or replace function xbase.has_workspace_role(ws uuid, roles text[]) returns boolean
language sql stable security definer set search_path = '' as $$
    select coalesce(xbase.workspace_role(ws) = any(roles), false)
$$;

-- Workspace creators automatically become owners (also backfills old rows).
create or replace function xbase.add_owner_membership() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
    insert into xbase.workspace_members (workspace_id, user_id, role)
    values (new.id, new.owner_id, 'owner')
    on conflict (workspace_id, user_id) do update set role = 'owner';
    return new;
end $$;

drop trigger if exists trg_workspaces_owner_membership on xbase.workspaces;
create trigger trg_workspaces_owner_membership after insert on xbase.workspaces
    for each row execute function xbase.add_owner_membership();

insert into xbase.workspace_members (workspace_id, user_id, role)
select id, owner_id, 'owner' from xbase.workspaces
on conflict (workspace_id, user_id) do nothing;

-- ---------------------------------------------------------------------------
-- 3. Invitations (token stored as SHA-256 hash only)
-- ---------------------------------------------------------------------------
create table if not exists xbase.workspace_invitations (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references xbase.workspaces(id) on delete cascade,
    email        text not null check (email = lower(email)),
    role         text not null default 'member' check (role in ('admin', 'member', 'viewer')),
    token_hash   text not null unique,
    invited_by   uuid not null,
    expires_at   timestamptz not null default now() + interval '7 days',
    accepted_at  timestamptz,
    accepted_by  uuid,
    revoked_at   timestamptz,
    created_at   timestamptz not null default now()
);
create unique index if not exists idx_invitations_pending
    on xbase.workspace_invitations (workspace_id, email)
    where accepted_at is null and revoked_at is null;

create or replace function xbase.accept_invitation(p_token_hash text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare
    inv     xbase.workspace_invitations;
    v_uid   uuid := auth.uid();
    v_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
begin
    if v_uid is null then
        raise exception 'authentication required';
    end if;

    select * into inv from xbase.workspace_invitations
     where token_hash = p_token_hash
     for update;

    if not found then raise exception 'invitation not found'; end if;
    if inv.revoked_at is not null then raise exception 'invitation has been revoked'; end if;
    if inv.accepted_at is not null then raise exception 'invitation was already accepted'; end if;
    if inv.expires_at < now() then raise exception 'invitation has expired'; end if;
    if inv.email <> v_email then raise exception 'invitation was sent to a different email address'; end if;

    insert into xbase.workspace_members (workspace_id, user_id, role)
    values (inv.workspace_id, v_uid, inv.role)
    on conflict (workspace_id, user_id) do nothing;

    update xbase.workspace_invitations
       set accepted_at = now(), accepted_by = v_uid
     where id = inv.id;

    return inv.workspace_id;
end $$;

-- ---------------------------------------------------------------------------
-- 4. API keys (server-to-server, SHA-256 hashed)
-- ---------------------------------------------------------------------------
create table if not exists xbase.api_keys (
    id           uuid primary key default gen_random_uuid(),
    app_slug     text not null references xbase.apps(slug) on delete cascade,
    workspace_id uuid not null references xbase.workspaces(id) on delete cascade,
    name         text not null,
    prefix       text not null,
    key_hash     text not null unique,
    scopes       text[] not null default '{}',
    created_by   uuid not null,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz
);
create index if not exists idx_api_keys_workspace on xbase.api_keys (workspace_id);

-- ---------------------------------------------------------------------------
-- 5. Webhook idempotency + durable job queue (backend-only tables)
-- ---------------------------------------------------------------------------
create table if not exists xbase.webhook_events (
    app_id       text not null,
    provider     text not null,
    event_id     text not null,
    event_type   text not null default '',
    payload      jsonb not null,
    received_at  timestamptz not null default now(),
    processed_at timestamptz,
    primary key (app_id, provider, event_id)
);

create table if not exists xbase.jobs (
    id           bigserial primary key,
    app_id       text not null,
    kind         text not null,
    payload      jsonb not null default '{}',
    status       text not null default 'queued'
                 check (status in ('queued', 'running', 'done', 'failed')),
    attempts     int not null default 0,
    max_attempts int not null default 8,
    run_at       timestamptz not null default now(),
    locked_at    timestamptz,
    last_error   text,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    finished_at  timestamptz
);
create index if not exists idx_jobs_ready on xbase.jobs (app_id, run_at, id) where status = 'queued';
create index if not exists idx_jobs_running on xbase.jobs (app_id, locked_at) where status = 'running';

-- ---------------------------------------------------------------------------
-- 6. Realtime change data capture (NOTIFY xbase_changes)
-- ---------------------------------------------------------------------------
create or replace function xbase.notify_change() returns trigger
language plpgsql as $$
declare
    rec     jsonb;
    payload jsonb;
begin
    rec := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
    rec := rec - 'embedding' - 'key_hash' - 'token_hash';
    payload := jsonb_build_object(
        'schema',       tg_table_schema,
        'table',        tg_table_name,
        'op',           tg_op,
        'id',           rec ->> 'id',
        'workspace_id', coalesce(rec ->> 'workspace_id',
                                 case when tg_table_name = 'workspaces' then rec ->> 'id' end),
        'app_slug',     rec ->> 'app_slug',
        'record',       rec
    );
    -- NOTIFY payloads are limited to 8000 bytes; clients refetch by id.
    if octet_length(payload::text) > 7800 then
        payload := payload - 'record';
    end if;
    perform pg_notify('xbase_changes', payload::text);
    return null;
end $$;

drop trigger if exists trg_workspaces_notify on xbase.workspaces;
create trigger trg_workspaces_notify after insert or update or delete on xbase.workspaces
    for each row execute function xbase.notify_change();

drop trigger if exists trg_workspace_members_notify on xbase.workspace_members;
create trigger trg_workspace_members_notify after insert or update or delete on xbase.workspace_members
    for each row execute function xbase.notify_change();

-- ---------------------------------------------------------------------------
-- 7. Row-Level Security
-- ---------------------------------------------------------------------------
alter table xbase.workspace_members     enable row level security;
alter table xbase.workspace_invitations enable row level security;
alter table xbase.api_keys              enable row level security;
alter table xbase.webhook_events        enable row level security;
alter table xbase.jobs                  enable row level security;

-- apps: readable registry
drop policy if exists "apps readable" on xbase.apps;
create policy "apps readable" on xbase.apps for select to authenticated using (true);

-- workspaces: members read, owner/admin rename, owner deletes
drop policy if exists "Users can view own workspaces" on xbase.workspaces;
drop policy if exists "Users can create own workspaces" on xbase.workspaces;
drop policy if exists "workspaces select" on xbase.workspaces;
drop policy if exists "workspaces insert" on xbase.workspaces;
drop policy if exists "workspaces update" on xbase.workspaces;
drop policy if exists "workspaces delete" on xbase.workspaces;

create policy "workspaces select" on xbase.workspaces for select to authenticated
    using (owner_id = (select auth.uid()) or xbase.is_workspace_member(id));
create policy "workspaces insert" on xbase.workspaces for insert to authenticated
    with check (owner_id = (select auth.uid()));
create policy "workspaces update" on xbase.workspaces for update to authenticated
    using (xbase.has_workspace_role(id, array['owner', 'admin']))
    with check (xbase.has_workspace_role(id, array['owner', 'admin']));
create policy "workspaces delete" on xbase.workspaces for delete to authenticated
    using (owner_id = (select auth.uid()));

-- members: members read; owner/admin manage non-owners; anyone may leave
drop policy if exists "members select" on xbase.workspace_members;
drop policy if exists "members update" on xbase.workspace_members;
drop policy if exists "members delete" on xbase.workspace_members;

create policy "members select" on xbase.workspace_members for select to authenticated
    using (xbase.is_workspace_member(workspace_id));
create policy "members update" on xbase.workspace_members for update to authenticated
    using (role <> 'owner' and xbase.has_workspace_role(workspace_id, array['owner', 'admin']))
    with check (role <> 'owner' and xbase.has_workspace_role(workspace_id, array['owner', 'admin']));
create policy "members delete" on xbase.workspace_members for delete to authenticated
    using (role <> 'owner' and (user_id = (select auth.uid())
           or xbase.has_workspace_role(workspace_id, array['owner', 'admin'])));

-- invitations: owner/admin only (acceptance goes through accept_invitation())
drop policy if exists "invitations select" on xbase.workspace_invitations;
drop policy if exists "invitations insert" on xbase.workspace_invitations;
drop policy if exists "invitations update" on xbase.workspace_invitations;

create policy "invitations select" on xbase.workspace_invitations for select to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin']));
create policy "invitations insert" on xbase.workspace_invitations for insert to authenticated
    with check (invited_by = (select auth.uid())
                and xbase.has_workspace_role(workspace_id, array['owner', 'admin']));
create policy "invitations update" on xbase.workspace_invitations for update to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin']));

-- api keys: owner/admin only
drop policy if exists "api_keys select" on xbase.api_keys;
drop policy if exists "api_keys insert" on xbase.api_keys;
drop policy if exists "api_keys update" on xbase.api_keys;

create policy "api_keys select" on xbase.api_keys for select to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin']));
create policy "api_keys insert" on xbase.api_keys for insert to authenticated
    with check (created_by = (select auth.uid())
                and xbase.has_workspace_role(workspace_id, array['owner', 'admin']));
create policy "api_keys update" on xbase.api_keys for update to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin']));

-- ---------------------------------------------------------------------------
-- 8. Grants (column-level where users must not touch billing/secret columns)
-- ---------------------------------------------------------------------------
grant usage on schema xbase to authenticated, service_role;

grant select on xbase.apps to authenticated;

grant select, delete on xbase.workspaces to authenticated;
grant insert (app_slug, name, owner_id) on xbase.workspaces to authenticated;
grant update (name) on xbase.workspaces to authenticated;

grant select, delete on xbase.workspace_members to authenticated;
grant update (role) on xbase.workspace_members to authenticated;

grant select on xbase.workspace_invitations to authenticated;
grant insert (workspace_id, email, role, token_hash, invited_by) on xbase.workspace_invitations to authenticated;
grant update (revoked_at) on xbase.workspace_invitations to authenticated;

grant select on xbase.api_keys to authenticated;
grant insert (app_slug, workspace_id, name, prefix, key_hash, scopes, created_by, expires_at)
    on xbase.api_keys to authenticated;
grant update (revoked_at) on xbase.api_keys to authenticated;

grant all on all tables in schema xbase to service_role;
grant usage, select on all sequences in schema xbase to service_role;

revoke all on function xbase.accept_invitation(text) from public, anon;
grant execute on function xbase.accept_invitation(text) to authenticated;
