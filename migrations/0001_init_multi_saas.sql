-- =============================================================================
-- xbase Multi-SaaS Starter Schema (PostgreSQL + Supabase RLS)
-- Designed for hosting 10+ SaaS applications on a single Supabase instance
-- =============================================================================

create extension if not exists "pgcrypto";

create schema if not exists xbase;

-- 1. Registry of SaaS applications hosted on this VPS
create table if not exists xbase.apps (
    slug text primary key,
    name text not null,
    created_at timestamptz not null default now()
);

-- 2. Multi-SaaS Workspaces / Tenants scoped to a specific app_slug
create table if not exists xbase.workspaces (
    id uuid primary key default gen_random_uuid(),
    app_slug text not null references xbase.apps(slug) on delete cascade,
    name text not null,
    owner_id uuid not null, -- references auth.users(id) in Supabase
    plan text not null default 'free',
    created_at timestamptz not null default now()
);

create index if not exists idx_workspaces_app_owner
    on xbase.workspaces (app_slug, owner_id);

-- 3. Enable Row-Level Security (RLS)
alter table xbase.apps enable row level security;
alter table xbase.workspaces enable row level security;

-- Authenticated users can read workspaces they own
create policy "Users can view own workspaces"
    on xbase.workspaces
    for select
    using (auth.uid() = owner_id);

create policy "Users can create own workspaces"
    on xbase.workspaces
    for insert
    with check (auth.uid() = owner_id);
