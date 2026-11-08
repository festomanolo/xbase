-- =============================================================================
-- 0004 — Shared rate limiter state (horizontal scaling)
--
-- With RATE_LIMIT_BACKEND=postgres every replica of every SaaS consumes the same
-- token bucket, so the configured limit holds no matter how many copies run.
-- The bucket math runs in ONE statement (upsert) so it is atomic under
-- concurrency and safe through Supavisor transaction pooling.
--
-- UNLOGGED: no WAL traffic for a hot, disposable table. After a crash the table
-- is empty, which only means buckets start full again.
-- =============================================================================

create unlogged table if not exists xbase.rate_limits (
    key         text primary key,
    tokens      double precision not null,
    updated_at  timestamptz not null default clock_timestamp()
);

create index if not exists rate_limits_updated_at_idx on xbase.rate_limits (updated_at);

alter table xbase.rate_limits enable row level security;   -- internal table: no policies

create or replace function xbase.rate_limit_check(p_key text, p_rate double precision, p_burst double precision)
returns table (allowed boolean, remaining double precision, retry_after double precision)
language plpgsql security definer set search_path = '' as $$
declare
    v_now    timestamptz := clock_timestamp();
    v_tokens double precision;
begin
    insert into xbase.rate_limits as r (key, tokens, updated_at)
    values (p_key, p_burst, v_now)
    on conflict (key) do update
        set tokens     = least(p_burst, r.tokens
                           + greatest(extract(epoch from (v_now - r.updated_at))::double precision, 0) * p_rate),
            updated_at = v_now
    returning r.tokens into v_tokens;

    if v_tokens >= 1 then
        update xbase.rate_limits set tokens = xbase.rate_limits.tokens - 1 where xbase.rate_limits.key = p_key;
        return query select true, v_tokens - 1, 0::double precision;
    else
        return query select false, 0::double precision, (1 - v_tokens) / greatest(p_rate, 0.001);
    end if;
end
$$;

revoke all on table xbase.rate_limits from public, anon, authenticated;
revoke all on function xbase.rate_limit_check(text, double precision, double precision) from public, anon, authenticated;
grant all on table xbase.rate_limits to service_role;
grant execute on function xbase.rate_limit_check(text, double precision, double precision) to service_role;
