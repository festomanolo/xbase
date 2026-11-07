-- =============================================================================
-- pgvector embeddings per workspace (semantic search / RAG).
--
-- Dimension 1536 matches OpenAI text-embedding-3-small. For other models
-- (e.g. nomic-embed-text = 768, all-MiniLM = 384) change vector(1536) below
-- BEFORE first deploy and set EMBEDDING_DIMS accordingly.
-- =============================================================================

create extension if not exists vector with schema extensions;

create table if not exists xbase.embeddings (
    id           uuid primary key default gen_random_uuid(),
    app_slug     text not null references xbase.apps(slug) on delete cascade,
    workspace_id uuid not null references xbase.workspaces(id) on delete cascade,
    external_id  text,
    content      text not null,
    metadata     jsonb not null default '{}',
    embedding    extensions.vector(1536) not null,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    unique (workspace_id, external_id)
);

create index if not exists idx_embeddings_workspace on xbase.embeddings (workspace_id);
create index if not exists idx_embeddings_metadata on xbase.embeddings using gin (metadata jsonb_path_ops);
create index if not exists idx_embeddings_hnsw
    on xbase.embeddings using hnsw (embedding extensions.vector_cosine_ops);

drop trigger if exists trg_embeddings_notify on xbase.embeddings;
create trigger trg_embeddings_notify after insert or update or delete on xbase.embeddings
    for each row execute function xbase.notify_change();

alter table xbase.embeddings enable row level security;

drop policy if exists "embeddings select" on xbase.embeddings;
drop policy if exists "embeddings insert" on xbase.embeddings;
drop policy if exists "embeddings update" on xbase.embeddings;
drop policy if exists "embeddings delete" on xbase.embeddings;

create policy "embeddings select" on xbase.embeddings for select to authenticated
    using (xbase.is_workspace_member(workspace_id));
create policy "embeddings insert" on xbase.embeddings for insert to authenticated
    with check (xbase.has_workspace_role(workspace_id, array['owner', 'admin', 'member']));
create policy "embeddings update" on xbase.embeddings for update to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin', 'member']));
create policy "embeddings delete" on xbase.embeddings for delete to authenticated
    using (xbase.has_workspace_role(workspace_id, array['owner', 'admin', 'member']));

grant select, insert, update, delete on xbase.embeddings to authenticated;
grant all on xbase.embeddings to service_role;
