//! Native realtime: WebSocket rooms with broadcast, presence tracking and
//! Postgres change data capture (LISTEN/NOTIFY on `xbase_changes`).
//!
//! Connect: `GET /ws?access_token=<supabase jwt>` (browsers cannot set headers
//! on WebSockets). Messages are JSON:
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
        Arc, Mutex,
    },
    time::Duration,
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
use serde::Deserialize;
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

#[derive(Default)]
struct Room {
    members: HashMap<ConnId, RoomMember>,
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
        }
    }

    pub fn publish_change(&self, event: ChangeEvent) {
        let _ = self.changes.send(Arc::new(event));
    }

    fn join(&self, room: &str, conn: ConnId, user_id: Uuid, tx: mpsc::Sender<Arc<str>>) -> Value {
        let mut rooms = self.rooms.lock().unwrap();
        let r = rooms.entry(room.to_string()).or_default();
        r.members.insert(conn, RoomMember { tx, user_id, presence: None });
        presence_snapshot(r)
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
                            && ev.app_slug.as_deref().map_or(true, |a| a == state.config.app_id);
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
