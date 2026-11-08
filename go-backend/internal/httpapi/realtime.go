package httpapi

// Realtime over WebSocket — same protocol as backend/src/realtime.rs.
//
//	GET /ws?access_token=<supabase jwt>
//
//	client → server  join | leave | broadcast | track | untrack |
//	                 subscribe_changes | unsubscribe_changes | access_token | ping
//	server → client  connected | joined | left | broadcast | presence_diff |
//	                 change | subscribed | unsubscribed | token_refreshed | error | pong
//
// Rooms are per process. With REALTIME_CLUSTER=true every broadcast / presence
// change is also published on the Postgres channel `xbase_rt_<app_id>` and
// replayed into the rooms of the other replicas; presence is replicated as diffs
// plus a 30 s "sync" heartbeat per room, and entries of a replica that falls
// silent expire after 90 s. The envelope format is identical to the Rust
// backend's. NOTIFY payloads are capped at ~8 KB, so clustered messages are
// limited to ~7 KB. Database changes (xbase_changes) reach every replica
// through its own LISTEN, so they need no replication.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/db"
)

const (
	changesChannel      = "xbase_changes"
	maxRoomsPerConn     = 50
	maxMessageBytes     = 64 * 1024
	outboundBuffer      = 256
	maxClusterBytes     = 7000
	maxEnvelopeBytes    = 7900
	presenceSyncEvery   = 30 * time.Second
	remotePresenceTTL   = 90 * time.Second
	heartbeatEvery      = 25 * time.Second
	writeTimeout        = 10 * time.Second
	listenReconnectBase = time.Second
	listenReconnectMax  = 30 * time.Second
)

// --- hub ------------------------------------------------------------------------

type wsConn struct {
	id     uint64
	send   chan []byte
	claims *auth.Claims

	mu         sync.Mutex // guards the two sets below
	rooms      map[string]bool
	workspaces map[string]bool
}

type member struct {
	conn     *wsConn
	userID   string
	tracking bool
	state    any
}

type remoteEntry struct {
	origin string
	userID string
	state  any
	seen   time.Time
}

type room struct {
	members map[uint64]*member
	remote  map[string]*remoteEntry // presence held by other replicas, keyed by conn id
}

type envelope struct {
	K        string                    `json:"k"` // msg | sync | req
	O        string                    `json:"o"`
	App      string                    `json:"app"`
	Room     string                    `json:"room"`
	Msg      map[string]any            `json:"msg,omitempty"`
	Presence map[string]map[string]any `json:"presence,omitempty"`
}

type hub struct {
	appID  string
	origin string

	mu    sync.Mutex
	rooms map[string]*room

	nextID atomic.Uint64
	conns  atomic.Int64

	cluster atomic.Pointer[chan string]
	pub     atomic.Uint64
	recv    atomic.Uint64
	drop    atomic.Uint64

	subsMu sync.RWMutex
	subs   map[*wsConn]struct{}
}

func newHub(appID string) *hub {
	h := &hub{appID: appID, origin: randomID(), rooms: map[string]*room{}, subs: map[*wsConn]struct{}{}}
	h.nextID.Store(1)
	return h
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// roomChannel is the Postgres channel for an app's cluster traffic.
func roomChannel(appID string) string {
	c := "xbase_rt_" + strings.ReplaceAll(appID, "-", "_")
	if len(c) > 63 {
		c = c[:63]
	}
	return c
}

// enableCluster turns on cross-replica fan-out. Connection ids (which double as
// presence keys) switch to a random 32-bit prefix, kept below 2^53 so
// JavaScript clients read them exactly, so ids never collide between replicas.
func (h *hub) enableCluster(out chan string) {
	if h.cluster.CompareAndSwap(nil, &out) {
		var b [4]byte
		_, _ = rand.Read(b[:])
		h.nextID.Store(uint64(binary.BigEndian.Uint32(b[:]))<<20 | 1)
	}
}

func (h *hub) clusterEnabled() bool { return h.cluster.Load() != nil }

func (h *hub) stats() (conns, rooms int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return int(h.conns.Load()), len(h.rooms)
}

func (h *hub) clusterCounters() (pub, recv, drop uint64) {
	return h.pub.Load(), h.recv.Load(), h.drop.Load()
}

func (h *hub) publish(env envelope) {
	out := h.cluster.Load()
	if out == nil {
		return
	}
	env.App = h.appID
	env.O = h.origin
	b, err := json.Marshal(env)
	if err == nil && len(b) <= maxEnvelopeBytes {
		select {
		case *out <- string(b):
			h.pub.Add(1)
			return
		default:
		}
	}
	h.drop.Add(1)
}

func (h *hub) publishMsg(roomName string, msg map[string]any) {
	h.publish(envelope{K: "msg", Room: roomName, Msg: msg})
}

// fanOut is non-blocking: a slow consumer drops messages instead of stalling the room.
func fanOut(r *room, skip *wsConn, msg map[string]any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	for _, m := range r.members {
		if m.conn != skip {
			select {
			case m.conn.send <- b:
			default:
			}
		}
	}
}

func (h *hub) join(roomName string, c *wsConn, userID string) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomName]
	if r == nil {
		r = &room{members: map[uint64]*member{}, remote: map[string]*remoteEntry{}}
		h.rooms[roomName] = r
	}
	firstLocal := len(r.members) == 0
	r.members[c.id] = &member{conn: c, userID: userID}
	snap := presenceSnapshot(r)
	if firstLocal {
		h.publish(envelope{K: "req", Room: roomName}) // ask other replicas for their presence
	}
	return snap
}

func (h *hub) leave(roomName string, c *wsConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomName]
	if r == nil {
		return
	}
	m := r.members[c.id]
	delete(r.members, c.id)
	if m != nil && m.tracking {
		diff := map[string]any{
			"type": "presence_diff", "room": roomName, "joins": map[string]any{},
			"leaves": map[string]any{idStr(c.id): map[string]any{"user_id": m.userID, "state": m.state}},
		}
		fanOut(r, nil, diff)
		h.publishMsg(roomName, diff)
	}
	if len(r.members) == 0 {
		delete(h.rooms, roomName)
	}
}

func (h *hub) broadcast(roomName string, from *wsConn, msg map[string]any) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomName]
	if r == nil || r.members[from.id] == nil {
		return false
	}
	fanOut(r, from, msg)
	h.publishMsg(roomName, msg)
	return true
}

// track sets (has=true) or clears (has=false) presence and tells the room.
func (h *hub) track(roomName string, c *wsConn, state any, has bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomName]
	if r == nil {
		return false
	}
	m := r.members[c.id]
	if m == nil {
		return false
	}
	joins, leaves := map[string]any{}, map[string]any{}
	if m.tracking {
		leaves[idStr(c.id)] = map[string]any{"user_id": m.userID, "state": m.state}
	}
	m.tracking, m.state = has, nil
	if has {
		m.state = state
		joins[idStr(c.id)] = map[string]any{"user_id": m.userID, "state": state}
	}
	diff := map[string]any{"type": "presence_diff", "room": roomName, "joins": joins, "leaves": leaves}
	fanOut(r, nil, diff)
	h.publishMsg(roomName, diff)
	return true
}

func idStr(id uint64) string { return uitoa(id) }

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func localPresence(r *room) map[string]map[string]any {
	out := map[string]map[string]any{}
	for id, m := range r.members {
		if m.tracking {
			out[uitoa(id)] = map[string]any{"user_id": m.userID, "state": m.state}
		}
	}
	return out
}

// presenceSnapshot is local plus replicated presence.
func presenceSnapshot(r *room) map[string]any {
	out := map[string]any{}
	for id, p := range localPresence(r) {
		out[id] = p
	}
	for id, e := range r.remote {
		out[id] = map[string]any{"user_id": e.userID, "state": e.state}
	}
	return out
}

// applyRemote applies an envelope published by another replica.
func (h *hub) applyRemote(env envelope) {
	if env.O == h.origin || env.App != h.appID || !h.clusterEnabled() {
		return
	}
	h.recv.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[env.Room]
	if r == nil {
		return
	}
	switch env.K {
	case "msg":
		if env.Msg["type"] == "presence_diff" {
			applyRemoteDiff(r, env.O, env.Msg)
		}
		fanOut(r, nil, env.Msg)
	case "sync":
		applyRemoteSync(r, env.Room, env.O, env.Presence)
	case "req":
		h.publishSync(env.Room, r)
	}
}

func (h *hub) publishSync(roomName string, r *room) {
	if p := localPresence(r); len(p) > 0 {
		h.publish(envelope{K: "sync", Room: roomName, Presence: p})
	}
}

func applyRemoteDiff(r *room, origin string, msg map[string]any) {
	if leaves, ok := msg["leaves"].(map[string]any); ok {
		for k := range leaves {
			delete(r.remote, k)
		}
	}
	if joins, ok := msg["joins"].(map[string]any); ok {
		for k, v := range joins {
			if e, ok := v.(map[string]any); ok {
				if uid, _ := e["user_id"].(string); uid != "" {
					r.remote[k] = &remoteEntry{origin: origin, userID: uid, state: e["state"], seen: time.Now()}
				}
			}
		}
	}
}

// applyRemoteSync replaces everything `origin` holds in the room and tells
// local members what changed.
func applyRemoteSync(r *room, name, origin string, presence map[string]map[string]any) {
	joins, leaves := map[string]any{}, map[string]any{}
	for k, e := range r.remote {
		if _, still := presence[k]; e.origin == origin && !still {
			delete(r.remote, k)
			leaves[k] = map[string]any{"user_id": e.userID, "state": e.state}
		}
	}
	for k, v := range presence {
		uid, _ := v["user_id"].(string)
		if uid == "" {
			continue
		}
		old, had := r.remote[k]
		r.remote[k] = &remoteEntry{origin: origin, userID: uid, state: v["state"], seen: time.Now()}
		if !had || !reflect.DeepEqual(old.state, v["state"]) {
			joins[k] = v
		}
	}
	if len(joins) > 0 || len(leaves) > 0 {
		fanOut(r, nil, map[string]any{"type": "presence_diff", "room": name, "joins": joins, "leaves": leaves})
	}
}

// requestAllPresence asks other replicas for presence of every room we hold
// (after (re)connecting the cluster listener).
func (h *hub) requestAllPresence() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name := range h.rooms {
		h.publish(envelope{K: "req", Room: name})
	}
}

// clusterTick re-announces our presence and expires entries from silent replicas.
func (h *hub) clusterTick() {
	h.mu.Lock()
	for name, r := range h.rooms {
		h.publishSync(name, r)
	}
	h.mu.Unlock()
	h.expireRemote(remotePresenceTTL)
}

func (h *hub) expireRemote(ttl time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name, r := range h.rooms {
		leaves := map[string]any{}
		for k, e := range r.remote {
			if time.Since(e.seen) > ttl {
				delete(r.remote, k)
				leaves[k] = map[string]any{"user_id": e.userID, "state": e.state}
			}
		}
		if len(leaves) > 0 {
			fanOut(r, nil, map[string]any{"type": "presence_diff", "room": name, "joins": map[string]any{}, "leaves": leaves})
		}
	}
}

// publishChange delivers a database change event to subscribed connections.
func (h *hub) publishChange(ev map[string]any) {
	ws, _ := ev["workspace_id"].(string)
	if ws == "" {
		return
	}
	if app, _ := ev["app_slug"].(string); app != "" && app != h.appID {
		return
	}
	msg := map[string]any{"type": "change"}
	for k, v := range ev {
		if k != "app_slug" {
			msg[k] = v
		}
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.subsMu.RLock()
	defer h.subsMu.RUnlock()
	for c := range h.subs {
		c.mu.Lock()
		want := c.workspaces[ws]
		c.mu.Unlock()
		if want {
			select {
			case c.send <- b:
			default:
			}
		}
	}
}

// --- server side -------------------------------------------------------------------

func (s *Server) realtimeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ws", s.wsHandler)
}

// StartBackground launches the realtime listener / cluster tasks and the
// periodic rate-limit sweep. It returns immediately; all goroutines stop with ctx.
func (s *Server) StartBackground(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.SweepRateLimits(ctx)
			}
		}
	}()

	if !s.cfg.RealtimeEnabled {
		return
	}
	if s.cfg.DirectDatabaseURL == "" {
		slog.Warn("DIRECT_DATABASE_URL not set; realtime database changes disabled")
		return
	}
	channels := []string{changesChannel}
	if s.cfg.RealtimeCluster {
		out := make(chan string, 1024)
		s.hub.enableCluster(out)
		channels = append(channels, roomChannel(s.cfg.AppID))
		go s.runClusterPublisher(ctx, out)
		go func() {
			t := time.NewTicker(presenceSyncEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.hub.clusterTick()
				}
			}
		}()
		slog.Info("realtime cluster fan-out enabled")
	}
	go s.runListener(ctx, channels)
}

// runClusterPublisher turns locally originated envelopes into pg_notify calls
// (NOTIFY is fine through the transaction-mode pooler).
func (s *Server) runClusterPublisher(ctx context.Context, out <-chan string) {
	channel := roomChannel(s.cfg.AppID)
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-out:
			if _, err := s.pool.Exec(ctx, "select pg_notify($1, $2)", channel, payload); err != nil {
				slog.Warn("cluster publish failed", "error", err)
			}
		}
	}
}

// runListener holds one session connection LISTENing on the change feed (and
// the cluster channel), reconnecting with backoff — a dropped LISTEN connection
// would otherwise silently stop all realtime delivery.
func (s *Server) runListener(ctx context.Context, channels []string) {
	backoff := listenReconnectBase
	cluster := roomChannel(s.cfg.AppID)
	for ctx.Err() == nil {
		err := func() error {
			conn, err := pgx.Connect(ctx, s.cfg.DirectDatabaseURL)
			if err != nil {
				return err
			}
			defer conn.Close(context.Background())
			for _, ch := range channels {
				if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
					return err
				}
			}
			slog.Info("realtime listener connected", "channels", channels)
			backoff = listenReconnectBase
			if s.hub.clusterEnabled() {
				s.hub.requestAllPresence()
			}
			for {
				n, err := conn.WaitForNotification(ctx)
				if err != nil {
					return err
				}
				if n.Channel == cluster && s.hub.clusterEnabled() {
					var env envelope
					if json.Unmarshal([]byte(n.Payload), &env) == nil {
						s.hub.applyRemote(env)
					}
					continue
				}
				var ev map[string]any
				if json.Unmarshal([]byte(n.Payload), &ev) == nil {
					s.hub.publishChange(ev)
				}
			}
		}()
		if ctx.Err() != nil {
			return
		}
		slog.Warn("realtime listener disconnected", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, listenReconnectMax)
	}
}

func claimsExpired(c *auth.Claims) bool {
	exp, ok := c.Raw["exp"].(float64)
	return ok && int64(exp) < time.Now().Unix()
}

func validRoom(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ':' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func (s *Server) wsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.RealtimeEnabled {
		writeAPIError(w, errUnavailable("Realtime is disabled"))
		return
	}
	token := r.URL.Query().Get("access_token")
	if token == "" {
		token = auth.BearerToken(r)
	}
	if token == "" {
		writeAPIError(w, errUnauthorized("access_token query parameter required"))
		return
	}
	claims, err := auth.Verify(token, s.cfg.JWTSecret)
	if err != nil {
		writeAPIError(w, errUnauthorized("Invalid or expired Supabase JWT"))
		return
	}
	if claims.Subject == "" {
		writeAPIError(w, errUnauthorized("A signed-in user token is required"))
		return
	}

	// The server's Read/Write timeouts are sized for JSON requests, not sockets.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	// Auth is the token in the query string, not a cookie, so cross-site
	// WebSocket hijacking does not apply; browsers on any origin may connect.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return // Accept already replied
	}
	ws.SetReadLimit(maxMessageBytes)
	s.serveConn(r.Context(), ws, claims)
}

func (s *Server) serveConn(parent context.Context, ws *websocket.Conn, claims *auth.Claims) {
	h := s.hub
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	c := &wsConn{
		id: h.nextID.Add(1) - 1, send: make(chan []byte, outboundBuffer), claims: claims,
		rooms: map[string]bool{}, workspaces: map[string]bool{},
	}
	h.conns.Add(1)
	h.subsMu.Lock()
	h.subs[c] = struct{}{}
	h.subsMu.Unlock()
	defer func() {
		h.subsMu.Lock()
		delete(h.subs, c)
		h.subsMu.Unlock()
		c.mu.Lock()
		names := make([]string, 0, len(c.rooms))
		for name := range c.rooms {
			names = append(names, name)
		}
		c.mu.Unlock()
		for _, name := range names {
			h.leave(name, c)
		}
		h.conns.Add(-1)
		_ = ws.CloseNow()
	}()

	// single writer
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-c.send:
				wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
				err := ws.Write(wctx, websocket.MessageText, b)
				wcancel()
				if err != nil {
					return
				}
			}
		}
	}()
	// heartbeat (Ping needs the reader below to be running)
	go func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(ctx, writeTimeout)
				err := ws.Ping(pctx)
				pcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	c.reply(ctx, map[string]any{"type": "connected", "conn_id": c.id, "user_id": claims.Subject})
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if claimsExpired(c.claims) {
			c.reply(ctx, map[string]any{"type": "error", "message": "token_expired"})
			return
		}
		if reply := s.handleClientMsg(ctx, c, data); reply != nil {
			c.reply(ctx, reply)
		}
	}
}

// reply queues a response, waiting (bounded by ctx) rather than dropping it.
func (c *wsConn) reply(ctx context.Context, msg map[string]any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case c.send <- b:
	case <-ctx.Done():
	}
}

func wsErr(m string) map[string]any { return map[string]any{"type": "error", "message": m} }

func (s *Server) isMember(ctx context.Context, claims *auth.Claims, workspaceID string) bool {
	if !isUUID(workspaceID) {
		return false
	}
	found := false
	err := db.WithRLS(ctx, s.pool, claims, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			"select exists(select 1 from xbase.workspaces where id = $1::uuid and app_slug = $2)",
			workspaceID, s.cfg.AppID).Scan(&found)
	})
	return err == nil && found
}

func (s *Server) handleClientMsg(ctx context.Context, c *wsConn, data []byte) map[string]any {
	h := s.hub
	var m struct {
		Type        string          `json:"type"`
		Room        string          `json:"room"`
		Event       string          `json:"event"`
		Payload     json.RawMessage `json:"payload"`
		State       json.RawMessage `json:"state"`
		WorkspaceID string          `json:"workspace_id"`
		Token       string          `json:"token"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return wsErr("invalid message: " + err.Error())
	}
	decode := func(raw json.RawMessage) any {
		var v any
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &v)
		}
		return v
	}

	switch m.Type {
	case "ping":
		return map[string]any{"type": "pong"}

	case "join":
		if !validRoom(m.Room) {
			return wsErr("invalid room name")
		}
		c.mu.Lock()
		count := len(c.rooms)
		c.mu.Unlock()
		if count >= maxRoomsPerConn {
			return wsErr("too many rooms")
		}
		if ws, ok := strings.CutPrefix(m.Room, "workspace:"); ok {
			if !isUUID(ws) {
				return wsErr("invalid workspace room")
			}
			if !s.isMember(ctx, c.claims, ws) {
				return wsErr("not a member of this workspace")
			}
		}
		snap := h.join(m.Room, c, c.claims.Subject)
		c.mu.Lock()
		c.rooms[m.Room] = true
		c.mu.Unlock()
		return map[string]any{"type": "joined", "room": m.Room, "presence_state": snap}

	case "leave":
		c.mu.Lock()
		had := c.rooms[m.Room]
		delete(c.rooms, m.Room)
		c.mu.Unlock()
		if had {
			h.leave(m.Room, c)
		}
		return map[string]any{"type": "left", "room": m.Room}

	case "broadcast":
		msg := map[string]any{
			"type": "broadcast", "room": m.Room, "event": m.Event,
			"payload": decode(m.Payload), "from": c.claims.Subject,
		}
		if h.clusterEnabled() {
			if b, _ := json.Marshal(msg); len(b) > maxClusterBytes {
				return wsErr("message too large for clustered realtime (max 7000 bytes)")
			}
		}
		if !h.broadcast(m.Room, c, msg) {
			return wsErr("join the room first")
		}
		return nil

	case "track":
		if h.clusterEnabled() && len(m.State) > maxClusterBytes/2 {
			return wsErr("presence state too large for clustered realtime (max 3500 bytes)")
		}
		if !h.track(m.Room, c, decode(m.State), true) {
			return wsErr("join the room first")
		}
		return nil

	case "untrack":
		h.track(m.Room, c, nil, false)
		return nil

	case "subscribe_changes":
		if !s.isMember(ctx, c.claims, m.WorkspaceID) {
			return wsErr("not a member of this workspace")
		}
		c.mu.Lock()
		c.workspaces[strings.ToLower(m.WorkspaceID)] = true
		c.mu.Unlock()
		return map[string]any{"type": "subscribed", "workspace_id": m.WorkspaceID}

	case "unsubscribe_changes":
		c.mu.Lock()
		delete(c.workspaces, strings.ToLower(m.WorkspaceID))
		c.mu.Unlock()
		return map[string]any{"type": "unsubscribed", "workspace_id": m.WorkspaceID}

	case "access_token":
		nc, err := auth.Verify(m.Token, s.cfg.JWTSecret)
		if err != nil || nc.Subject != c.claims.Subject {
			return wsErr("invalid token")
		}
		c.claims = nc
		return map[string]any{"type": "token_refreshed"}
	}
	return wsErr("invalid message: unknown type")
}
