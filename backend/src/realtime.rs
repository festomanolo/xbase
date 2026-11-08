//! Native realtime: WebSocket rooms with broadcast, presence tracking and
//! Postgres change data capture (LISTEN/NOTIFY on `xbase_changes`).
//!
//! Connect: `GET /ws?access_token=<supabase jwt>` (browsers cannot set headers
//! on WebSockets).
//!
//! Horizontal scaling (`REALTIME_CLUSTER=true`): rooms are per-process, so every
//! broadcast / presence change is also published on the Postgres channel
//! `xbase_rt_<app_id>` and replayed into the rooms of every *other* replica.
//! Presence is replicated as diffs plus a 30 s full "sync" heartbeat per room;
//! entries of a replica that stops syncing expire after 90 s. NOTIFY payloads
//! are capped at ~8 KB, so clustered messages are limited to ~7 KB.
//!
//! Messages are JSON:
//!
//! client → server
//!   {"type":"join","room":"lobby"}                 public room
//!   {"type":"join","room":"workspace:<uuid>"}      private room, members only
//!   {"type":"leave","room":"lobby"}
//!   {"type":"broadcast","room":"lobby","event":"cursor","payload":{...}}
//!   {"type":"track","room":"lobby","state":{...}}  presence
//!   {"type":"untrack","room":"lobby"}
//!   {"type":"subscribe_changes","workspace_id":"<uuid>"}
//!   {"type":"unsubscribe_changes","workspace_id":"<uuid>"}
//!   {"type":"access_token","token":"<refreshed jwt>"}
//!   {"type":"ping"}
//!
//! server → client
//!   joined / left / broadcast / presence_state / presence_diff / change / error / pong

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    response::Response,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgListener;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::{
    auth::{bearer_token, verify_supabase_jwt, SupabaseClaims},
    error::{ApiError, ApiResult},
    rls::begin_rls,
    state::AppState,
};

pub const CHANGES_CHANNEL: &str = "xbase_changes";
const MAX_ROOMS_PER_CONN: usize = 50;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const OUTBOUND_BUFFER: usize = 256;

type ConnId = u64;

struct RoomMember {
    tx: mpsc::Sender<Arc<str>>,
    user_id: Uuid,
    presence: Option<Value>,
}

/// Presence entry mirrored from another replica.
struct RemoteEntry {
    origin: String,
    user_id: Uuid,
    state: Value,
    seen: Instant,
}

#[derive(Default)]
struct Room {
    members: HashMap<ConnId, RoomMember>,
    /// Presence held by connections on other replicas, keyed by conn id.
    remote: HashMap<String, RemoteEntry>,
}

/// Largest cluster payload we publish (Postgres NOTIFY allows < 8000 bytes).
pub const MAX_CLUSTER_BYTES: usize = 7000;
const MAX_ENVELOPE_BYTES: usize = 7900;
const PRESENCE_SYNC_EVERY: Duration = Duration::from_secs(30);
const REMOTE_PRESENCE_TTL: Duration = Duration::from_secs(90);

struct ClusterLink {
    tx: mpsc::Sender<String>,
    app: String,
}

/// Wire format on the cluster channel. `o` = origin replica id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Envelope {
    /// A message (broadcast or presence_diff) to replay into local room members.
    Msg { o: String, app: String, room: String, msg: Value },
    /// Full presence of the origin replica for one room.
    Sync { o: String, app: String, room: String, presence: serde_json::Map<String, Value> },
    /// "I just got my first member in this room; please Sync it to me."
    Req { o: String, app: String, room: String },
}

/// Postgres channel for a SaaS app's cluster traffic (identifier-safe, <= 63 bytes).
pub fn room_channel(app_id: &str) -> String {
    let mut c = format!("xbase_rt_{}", app_id.replace('-', "_"));
    c.truncate(63);
    c
}

/// Change event decoded from `pg_notify('xbase_changes', ...)`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangeEvent {
    pub schema: String,
    pub table: String,
    pub op: String,
    pub workspace_id: Option<Uuid>,
    pub app_slug: Option<String>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

pub struct RealtimeHub {
    rooms: Mutex<HashMap<String, Room>>,
    changes: broadcast::Sender<Arc<ChangeEvent>>,
    next_id: AtomicU64,
    pub connections: AtomicU64,
    origin: String,
    cluster: OnceLock<ClusterLink>,
    pub cluster_published: AtomicU64,
    pub cluster_received: AtomicU64,
    pub cluster_dropped: AtomicU64,
}

impl Default for RealtimeHub {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeHub {
    pub fn new() -> Self {
        let (changes, _) = broadcast::channel(1024);
        Self {
            rooms: Mutex::new(HashMap::new()),
            changes,
            next_id: AtomicU64::new(1),
            connections: AtomicU64::new(0),
            origin: Uuid::new_v4().to_string(),
            cluster: OnceLock::new(),
            cluster_published: AtomicU64::new(0),
            cluster_received: AtomicU64::new(0),
            cluster_dropped: AtomicU64::new(0),
        }
    }

    /// Turns on cross-replica fan-out. Connection ids switch to a random 32-bit
    /// prefix (kept below 2^53 so JavaScript clients read them exactly) so ids
    /// — which double as presence keys — never collide between replicas.
    pub fn enable_cluster(&self, app_id: &str, tx: mpsc::Sender<String>) {
        if self.cluster.set(ClusterLink { tx, app: app_id.to_string() }).is_ok() {
            self.next_id.store(((rand::random::<u32>() as u64) << 20) | 1, Ordering::Relaxed);
        }
    }

    pub fn cluster_enabled(&self) -> bool {
        self.cluster.get().is_some()
    }

    fn publish(&self, env: &Envelope) {
        let Some(link) = self.cluster.get() else { return };
        let sent = serde_json::to_string(env)
            .ok()
            .filter(|s| s.len() <= MAX_ENVELOPE_BYTES)
            .is_some_and(|s| link.tx.try_send(s).is_ok());
        let counter = if sent { &self.cluster_published } else { &self.cluster_dropped };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn for_us(&self, origin: &str, app: &str) -> bool {
        origin != self.origin && self.cluster.get().is_some_and(|l| l.app == app)
    }

    /// Applies an envelope published by another replica.
    pub fn apply_remote(&self, env: Envelope) {
        match env {
            Envelope::Msg { o, app, room, msg } => {
                if !self.for_us(&o, &app) {
                    return;
                }
                self.cluster_received.fetch_add(1, Ordering::Relaxed);
                let mut rooms = self.rooms.lock().unwrap();
                let Some(r) = rooms.get_mut(&room) else { return };
                if msg["type"] == "presence_diff" {
                    apply_remote_diff(r, &o, &msg);
                }
                fan_out(r, None, &msg);
            }
            Envelope::Sync { o, app, room, presence } => {
                if !self.for_us(&o, &app) {
                    return;
                }
                self.cluster_received.fetch_add(1, Ordering::Relaxed);
                let mut rooms = self.rooms.lock().unwrap();
                let Some(r) = rooms.get_mut(&room) else { return };
                apply_remote_sync(r, &room, &o, presence);
            }
            Envelope::Req { o, app, room } => {
                if !self.for_us(&o, &app) {
                    return;
                }
                self.cluster_received.fetch_add(1, Ordering::Relaxed);
                let rooms = self.rooms.lock().unwrap();
                if let Some(r) = rooms.get(&room) {
                    self.publish_sync(&room, r);
                }
            }
        }
    }

    fn publish_sync(&self, room: &str, r: &Room) {
        let presence = local_presence(r);
        if presence.is_empty() {
            return;
        }
        if let Some(link) = self.cluster.get() {
            self.publish(&Envelope::Sync {
                o: self.origin.clone(),
                app: link.app.clone(),
                room: room.to_string(),
                presence,
            });
        }
    }

    /// Asks other replicas for presence of every room we hold (after (re)connecting).
    pub fn request_all_presence(&self) {
        let Some(link) = self.cluster.get() else { return };
        let rooms = self.rooms.lock().unwrap();
        for room in rooms.keys() {
            self.publish(&Envelope::Req { o: self.origin.clone(), app: link.app.clone(), room: room.clone() });
        }
    }

    /// Periodic housekeeping: re-announce our presence and expire entries from
    /// replicas that went silent.
    pub fn cluster_tick(&self) {
        {
            let rooms = self.rooms.lock().unwrap();
            for (name, r) in rooms.iter() {
                self.publish_sync(name, r);
            }
        }
        self.expire_remote(REMOTE_PRESENCE_TTL);
    }

    fn expire_remote(&self, ttl: Duration) {
        let mut rooms = self.rooms.lock().unwrap();
        for (name, r) in rooms.iter_mut() {
            let dead: Vec<String> = r
                .remote
                .iter()
                .filter(|(_, e)| e.seen.elapsed() > ttl)
                .map(|(k, _)| k.clone())
                .collect();
            if dead.is_empty() {
                continue;
            }
            let leaves: serde_json::Map<String, Value> = dead
                .into_iter()
                .filter_map(|k| {
                    r.remote
                        .remove(&k)
                        .map(|e| (k, json!({ "user_id": e.user_id, "state": e.state })))
                })
                .collect();
            fan_out(r, None, &json!({ "type": "presence_diff", "room": name, "joins": {}, "leaves": leaves }));
        }
    }

    pub fn publish_change(&self, event: ChangeEvent) {
        let _ = self.changes.send(Arc::new(event));
    }

    fn join(&self, room: &str, conn: ConnId, user_id: Uuid, tx: mpsc::Sender<Arc<str>>) -> Value {
        let mut rooms = self.rooms.lock().unwrap();
        let r = rooms.entry(room.to_string()).or_default();
        let first_local = r.members.is_empty();
        r.members.insert(conn, RoomMember { tx, user_id, presence: None });
        let snapshot = presence_snapshot(r);
        if first_local {
            if let Some(link) = self.cluster.get() {
                self.publish(&Envelope::Req { o: self.origin.clone(), app: link.app.clone(), room: room.to_string() });
            }
        }
        snapshot
    }

    fn leave(&self, room: &str, conn: ConnId) {
        let mut rooms = self.rooms.lock().unwrap();
        let Some(r) = rooms.get_mut(room) else { return };
        let had_presence = r
            .members
            .remove(&conn)
            .and_then(|m| m.presence.map(|p| (m.user_id, p)));
        if let Some((user_id, state)) = had_presence {
            let diff = json!({
                "type": "presence_diff", "room": room, "joins": {},
                "leaves": { conn.to_string(): { "user_id": user_id, "state": state } }
            });
            fan_out(r, None, &diff);
            self.publish_msg(room, diff);
        }
        if r.members.is_empty() {
            rooms.remove(room);
        }
    }

    fn broadcast(&self, room: &str, from: ConnId, msg: &Value) -> bool {
        let rooms = self.rooms.lock().unwrap();
        match rooms.get(room) {
            Some(r) if r.members.contains_key(&from) => {
                fan_out(r, Some(from), msg);
                self.publish_msg(room, msg.clone());
                true
            }
            _ => false,
        }
    }

    fn track(&self, room: &str, conn: ConnId, state: Option<Value>) -> bool {
        let mut rooms = self.rooms.lock().unwrap();
        let Some(r) = rooms.get_mut(room) else { return false };
        let Some(member) = r.members.get_mut(&conn) else { return false };
        let user_id = member.user_id;
        let previous = std::mem::replace(&mut member.presence, state.clone());
        let key = conn.to_string();
        let leaves = previous
            .map(|p| json!({ key.clone(): { "user_id": user_id, "state": p } }))
            .unwrap_or_else(|| json!({}));
        let joins = state
            .map(|s| json!({ key: { "user_id": user_id, "state": s } }))
            .unwrap_or_else(|| json!({}));
        let diff = json!({ "type": "presence_diff", "room": room, "joins": joins, "leaves": leaves });
        fan_out(r, None, &diff);
        true
    }

    pub fn room_count(&self) -> usize {
        self.rooms.lock().unwrap().len()
    }
}

fn presence_snapshot(room: &Room) -> Value {
    let presences: serde_json::Map<String, Value> = room
        .members
        .iter()
        .filter_map(|(id, m)| {
            m.presence
                .as_ref()
                .map(|p| (id.to_string(), json!({ "user_id": m.user_id, "state": p })))
        })
        .collect();
    Value::Object(presences)
}

/// Non-blocking fan-out; slow consumers drop messages instead of stalling the room.
fn fan_out(room: &Room, skip: Option<ConnId>, msg: &Value) {
    let text: Arc<str> = Arc::from(msg.to_string());
    for (id, m) in &room.members {
        if Some(*id) != skip {
            let _ = m.tx.try_send(text.clone());
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(ws_handler))
}

#[derive(Deserialize)]
struct WsQuery {
    access_token: Option<String>,
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(q): Query<WsQuery>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !state.config.realtime_enabled {
        return Err(ApiError::ServiceUnavailable("Realtime is disabled".into()));
    }
    let token = q
        .access_token
        .as_deref()
        .or_else(|| bearer_token(&headers))
        .ok_or_else(|| ApiError::Unauthorized("access_token query parameter required".into()))?;
    let claims = verify_supabase_jwt(token, &state.config.supabase_jwt_secret)
        .map_err(|_| ApiError::Unauthorized("Invalid or expired Supabase JWT".into()))?;
    if claims.sub.is_nil() {
        return Err(ApiError::Unauthorized("A signed-in user token is required".into()));
    }

    Ok(ws
        .max_message_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| run_connection(state, claims, socket)))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Join { room: String },
    Leave { room: String },
    Broadcast { room: String, event: String, #[serde(default)] payload: Value },
    Track { room: String, #[serde(default)] state: Value },
    Untrack { room: String },
    SubscribeChanges { workspace_id: Uuid },
    UnsubscribeChanges { workspace_id: Uuid },
    AccessToken { token: String },
    Ping,
}

struct Conn {
    id: ConnId,
    claims: SupabaseClaims,
    rooms: HashSet<String>,
    workspaces: HashSet<Uuid>,
}

async fn is_member(state: &AppState, claims: &SupabaseClaims, workspace_id: Uuid) -> bool {
    let Ok(mut tx) = begin_rls(&state.pool, claims).await else { return false };
    let found = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from xbase.workspaces where id = $1 and app_slug = $2)",
    )
    .bind(workspace_id)
    .bind(&state.config.app_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);
    let _ = tx.commit().await;
    found
}

fn valid_room(room: &str) -> bool {
    !room.is_empty()
        && room.len() <= 128
        && room
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
}

async fn run_connection(state: AppState, claims: SupabaseClaims, mut socket: WebSocket) {
    let hub = state.realtime.clone();
    hub.connections.fetch_add(1, Ordering::Relaxed);
    let (out_tx, mut out_rx) = mpsc::channel::<Arc<str>>(OUTBOUND_BUFFER);
    let mut changes_rx = hub.changes.subscribe();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
    let mut conn = Conn {
        id: hub.next_id.fetch_add(1, Ordering::Relaxed),
        claims,
        rooms: HashSet::new(),
        workspaces: HashSet::new(),
    };

    let hello = json!({ "type": "connected", "conn_id": conn.id, "user_id": conn.claims.sub });
    if socket.send(Message::Text(hello.to_string())).await.is_err() {
        hub.connections.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    _ => continue,
                };
                if conn.claims.is_expired() {
                    let _ = socket.send(Message::Text(json!({"type":"error","message":"token_expired"}).to_string())).await;
                    break;
                }
                let reply = handle_client_msg(&state, &mut conn, &out_tx, &text).await;
                if let Some(reply) = reply {
                    if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                }
            }
            Some(out) = out_rx.recv() => {
                if socket.send(Message::Text(out.to_string())).await.is_err() { break; }
            }
            change = changes_rx.recv(), if !conn.workspaces.is_empty() => {
                match change {
                    Ok(ev) => {
                        let relevant = ev.workspace_id.is_some_and(|w| conn.workspaces.contains(&w))
                            && ev.app_slug.as_deref().is_none_or(|a| a == state.config.app_id);
                        if relevant {
                            let mut msg = json!({ "type": "change", "schema": ev.schema, "table": ev.table, "op": ev.op, "workspace_id": ev.workspace_id });
                            for (k, v) in &ev.rest { msg[k] = v.clone(); }
                            if socket.send(Message::Text(msg.to_string())).await.is_err() { break; }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let warn = json!({"type":"error","message":"changes_lagged","dropped":n});
                        if socket.send(Message::Text(warn.to_string())).await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() { break; }
            }
        }
    }

    for room in conn.rooms.drain() {
        hub.leave(&room, conn.id);
    }
    hub.connections.fetch_sub(1, Ordering::Relaxed);
}

async fn handle_client_msg(
    state: &AppState,
    conn: &mut Conn,
    out_tx: &mpsc::Sender<Arc<str>>,
    text: &str,
) -> Option<Value> {
    let hub = &state.realtime;
    let msg: ClientMsg = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => return Some(json!({ "type": "error", "message": format!("invalid message: {e}") })),
    };
    let err = |m: &str| Some(json!({ "type": "error", "message": m }));

    match msg {
        ClientMsg::Ping => Some(json!({ "type": "pong" })),
        ClientMsg::Join { room } => {
            if !valid_room(&room) {
                return err("invalid room name");
            }
            if conn.rooms.len() >= MAX_ROOMS_PER_CONN {
                return err("too many rooms");
            }
            if let Some(ws) = room.strip_prefix("workspace:") {
                let Ok(ws) = Uuid::parse_str(ws) else { return err("invalid workspace room") };
                if !is_member(state, &conn.claims, ws).await {
                    return err("not a member of this workspace");
                }
            }
            let presences = hub.join(&room, conn.id, conn.claims.sub, out_tx.clone());
            conn.rooms.insert(room.clone());
            Some(json!({ "type": "joined", "room": room, "presence_state": presences }))
        }
        ClientMsg::Leave { room } => {
            if conn.rooms.remove(&room) {
                hub.leave(&room, conn.id);
            }
            Some(json!({ "type": "left", "room": room }))
        }
        ClientMsg::Broadcast { room, event, payload } => {
            let msg = json!({
                "type": "broadcast", "room": room, "event": event,
                "payload": payload, "from": conn.claims.sub
            });
            if hub.broadcast(&room, conn.id, &msg) { None } else { err("join the room first") }
        }
        ClientMsg::Track { room, state } => {
            if hub.track(&room, conn.id, Some(state)) { None } else { err("join the room first") }
        }
        ClientMsg::Untrack { room } => {
            hub.track(&room, conn.id, None);
            None
        }
        ClientMsg::SubscribeChanges { workspace_id } => {
            if !is_member(state, &conn.claims, workspace_id).await {
                return err("not a member of this workspace");
            }
            conn.workspaces.insert(workspace_id);
            Some(json!({ "type": "subscribed", "workspace_id": workspace_id }))
        }
        ClientMsg::UnsubscribeChanges { workspace_id } => {
            conn.workspaces.remove(&workspace_id);
            Some(json!({ "type": "unsubscribed", "workspace_id": workspace_id }))
        }
        ClientMsg::AccessToken { token } => {
            match verify_supabase_jwt(&token, &state.config.supabase_jwt_secret) {
                Ok(c) if c.sub == conn.claims.sub => {
                    conn.claims = c;
                    Some(json!({ "type": "token_refreshed" }))
                }
                _ => err("invalid token"),
            }
        }
    }
}

/// Bridges Postgres `NOTIFY xbase_changes` into the hub. Needs a direct session
/// connection (port 5432); transaction-mode poolers cannot hold LISTEN.
pub async fn run_change_listener(hub: Arc<RealtimeHub>, direct_url: String) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match PgListener::connect(&direct_url).await {
            Ok(mut listener) => {
                if let Err(e) = listener.listen(CHANGES_CHANNEL).await {
                    tracing::warn!(error = %e, "LISTEN failed");
                } else {
                    tracing::info!(channel = CHANGES_CHANNEL, "realtime change listener connected");
                    backoff = Duration::from_secs(1);
                    loop {
                        match listener.recv().await {
                            Ok(n) => match serde_json::from_str::<ChangeEvent>(n.payload()) {
                                Ok(ev) => hub.publish_change(ev),
                                Err(e) => tracing::debug!(error = %e, "ignoring malformed change payload"),
                            },
                            Err(e) => {
                                tracing::warn!(error = %e, "change listener disconnected");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "change listener connect failed"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rooms_broadcast_and_presence() {
        let hub = RealtimeHub::new();
        let (a_tx, mut a_rx) = mpsc::channel(8);
        let (b_tx, mut b_rx) = mpsc::channel(8);
        let (ua, ub) = (Uuid::new_v4(), Uuid::new_v4());

        hub.join("lobby", 1, ua, a_tx);
        hub.join("lobby", 2, ub, b_tx);

        assert!(hub.broadcast("lobby", 1, &json!({"type":"broadcast","payload":1})));
        let got: Value = serde_json::from_str(&b_rx.recv().await.unwrap()).unwrap();
        assert_eq!(got["payload"], 1);
        assert!(a_rx.try_recv().is_err(), "sender does not receive its own broadcast");

        assert!(hub.track("lobby", 1, Some(json!({"status":"online"}))));
        let diff: Value = serde_json::from_str(&b_rx.recv().await.unwrap()).unwrap();
        assert_eq!(diff["type"], "presence_diff");
        assert_eq!(diff["joins"]["1"]["state"]["status"], "online");

        let (c_tx, _c_rx) = mpsc::channel(8);
        let snapshot = hub.join("lobby", 3, Uuid::new_v4(), c_tx);
        assert_eq!(snapshot["1"]["user_id"], json!(ua));

        hub.leave("lobby", 1);
        let _ = a_rx.try_recv();
        let leave: Value = serde_json::from_str(&b_rx.recv().await.unwrap()).unwrap();
        assert_eq!(leave["leaves"]["1"]["state"]["status"], "online");

        hub.leave("lobby", 2);
        hub.leave("lobby", 3);
        assert_eq!(hub.room_count(), 0);
    }

    #[test]
    fn non_members_cannot_broadcast() {
        let hub = RealtimeHub::new();
        assert!(!hub.broadcast("lobby", 9, &json!({})));
    }

    #[test]
    fn parses_change_payloads() {
        let ws = Uuid::new_v4();
        let ev: ChangeEvent = serde_json::from_str(&format!(
            r#"{{"schema":"xbase","table":"workspaces","op":"UPDATE","workspace_id":"{ws}","app_slug":"a","record":{{"name":"x"}}}}"#
        ))
        .unwrap();
        assert_eq!(ev.workspace_id, Some(ws));
        assert_eq!(ev.rest["record"]["name"], "x");
    }
}
