package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/config"
	"github.com/festomanolo/xbase/go-backend/internal/ratelimit"
)

func serverWith(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	cfg := &config.Config{
		AppID: "saas-test", JWTSecret: secret, TrustProxyHeaders: true, RealtimeEnabled: true,
		StorageURL: "http://127.0.0.1:1/storage/v1", SupabasePublicURL: "https://api.example.com",
		SupabaseServiceKey: "service-key", SupabaseAnonKey: "anon-key", EmbeddingDims: 3,
		StripePricePlans: map[string]string{}, LemonSqueezyVariantPlans: map[string]string{},
	}
	if mutate != nil {
		mutate(cfg)
	}
	// Lazily-connecting pool pointing nowhere: these tests never need a database.
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return New(cfg, pool, ratelimit.New(100, 1000))
}

const ws1 = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

func TestScopedBucketAndObjectPaths(t *testing.T) {
	if b, e := scopedBucket("app1", "avatars"); e != nil || b != "app1-avatars" {
		t.Fatalf("got %q %v", b, e)
	}
	if b, _ := scopedBucket("app1", "app1-avatars"); b != "app1-avatars" {
		t.Fatalf("already scoped bucket changed: %q", b)
	}
	for _, bad := range []string{"", "Bad Name", "a/b", strings.Repeat("x", 64)} {
		if _, e := scopedBucket("app1", bad); e == nil {
			t.Errorf("bucket %q should be rejected", bad)
		}
	}
	if p, e := validateObjectPath("/u/1/a.png"); e != nil || p != "u/1/a.png" {
		t.Fatalf("got %q %v", p, e)
	}
	for _, bad := range []string{"u/../etc/passwd", "u//a", "", "./a"} {
		if _, e := validateObjectPath(bad); e == nil {
			t.Errorf("path %q should be rejected", bad)
		}
	}
}

func TestAPIKeysAreConfinedToTheirWorkspaceFolder(t *testing.T) {
	other := "11111111-1111-1111-1111-111111111111"
	rw := &storageCaller{key: &keyPrincipal{WorkspaceID: ws1, Scopes: []string{"storage:read", "storage:write"}}}
	if _, e := rw.objectPath(ws1+"/a/b.png", true); e != nil {
		t.Fatalf("own folder rejected: %v", e)
	}
	for _, bad := range []string{other + "/a.png", "a.png", ws1 + "/../" + other + "/a.png"} {
		if _, e := rw.objectPath(bad, false); e == nil {
			t.Errorf("%q should be forbidden", bad)
		}
	}
	if p, _ := rw.listPrefix(""); p != ws1 {
		t.Fatalf("empty prefix should pin to workspace, got %q", p)
	}
	if p, _ := rw.listPrefix("/" + ws1 + "/docs/"); p != ws1+"/docs" {
		t.Fatalf("got %q", p)
	}
	if _, e := rw.listPrefix(other); e == nil {
		t.Fatal("foreign prefix must be rejected")
	}

	ro := &storageCaller{key: &keyPrincipal{WorkspaceID: ws1, Scopes: []string{"storage:read"}}}
	if _, e := ro.objectPath(ws1+"/a", false); e != nil {
		t.Fatal("read should be allowed")
	}
	if _, e := ro.objectPath(ws1+"/a", true); e == nil {
		t.Fatal("write must need storage:write")
	}
	none := &storageCaller{key: &keyPrincipal{WorkspaceID: ws1, Scopes: []string{"embeddings:read"}}}
	if _, e := none.listPrefix(""); e == nil {
		t.Fatal("list must need storage:read")
	}
	if _, e := (&storageCaller{key: &keyPrincipal{WorkspaceID: ws1, Scopes: []string{"*"}}}).objectPath(ws1+"/a", true); e != nil {
		t.Fatal("wildcard scope should pass")
	}
	// users are unconfined here — Storage RLS decides
	if p, e := (&storageCaller{token: "t"}).objectPath("anything/at/all", true); e != nil || p != "anything/at/all" {
		t.Fatal("users pass through")
	}
}

// A fake Supabase Storage that records what the proxy sent it.
func fakeStorage(t *testing.T) (*httptest.Server, *[]*http.Request, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var reqs []*http.Request
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, r)
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/object/list/"):
			_, _ = w.Write([]byte(`[{"name":"a.png"}]`))
		case strings.Contains(r.URL.Path, "/object/sign/"):
			_, _ = w.Write([]byte(`{"signedURL":"/object/sign/app-docs/x?token=abc"}`))
		case strings.Contains(r.URL.Path, "/object/authenticated/"):
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("PNGDATA"))
		case strings.HasSuffix(r.URL.Path, "/bucket") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"saas-test-docs"},{"id":"other-app-docs"}]`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"denied by RLS"}`))
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &reqs, &bodies
}

func TestStorageProxyForwardsUserTokenAndScopesBuckets(t *testing.T) {
	up, reqs, bodies := fakeStorage(t)
	srv := serverWith(t, func(c *config.Config) { c.StorageURL = up.URL + "/storage/v1" })
	h := srv.Handler()
	tok := sign(t, "11111111-1111-1111-1111-111111111111", "authenticated")

	req := httptest.NewRequest("POST", "/api/v1/storage/objects/docs/list", strings.NewReader(`{"prefix":"u1","limit":5000}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := do(h, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "a.png") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got := (*reqs)[0]
	if got.URL.Path != "/storage/v1/object/list/saas-test-docs" {
		t.Errorf("bucket not app-scoped: %s", got.URL.Path)
	}
	if got.Header.Get("Authorization") != "Bearer "+tok || got.Header.Get("apikey") != "anon-key" {
		t.Errorf("user identity not forwarded: %v", got.Header)
	}
	if !strings.Contains((*bodies)[0], `"limit":1000`) || !strings.Contains((*bodies)[0], `"prefix":"u1"`) {
		t.Errorf("limit not capped / prefix lost: %s", (*bodies)[0])
	}

	// sign-download rewrites the relative URL onto the public host
	req = httptest.NewRequest("POST", "/api/v1/storage/objects/docs/sign-download", strings.NewReader(`{"path":"u1/a b.png","download":"x.png"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = do(h, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || !strings.HasPrefix(fmt.Sprint(out["signed_url"]), "https://api.example.com/storage/v1/object/sign/app-docs/x?token=abc&download=x.png") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if p := (*reqs)[1].URL.EscapedPath(); p != "/storage/v1/object/sign/saas-test-docs/u1/a%20b.png" {
		t.Errorf("object path not escaped: %s", p)
	}

	// streaming download + header passthrough
	req = httptest.NewRequest("GET", "/api/v1/storage/objects/docs/u1/a.png", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = do(h, req)
	if rec.Code != 200 || rec.Body.String() != "PNGDATA" || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("status=%d ct=%s body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}

	// upstream RLS denial is forwarded verbatim
	req = httptest.NewRequest("PUT", "/api/v1/storage/objects/docs/u1/new.png", strings.NewReader("bytes"))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = do(h, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "denied by RLS") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if last := (*reqs)[len(*reqs)-1]; last.Header.Get("x-upsert") != "true" || last.Method != "PUT" {
		t.Errorf("PUT must upsert: %v %s", last.Header, last.Method)
	}

	// traversal never reaches upstream
	n := len(*reqs)
	req = httptest.NewRequest("POST", "/api/v1/storage/objects/docs/sign-upload", strings.NewReader(`{"path":"a/../b"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	if rec = do(h, req); rec.Code != 400 || len(*reqs) != n {
		t.Fatalf("traversal: status=%d upstream calls=%d", rec.Code, len(*reqs)-n)
	}
}

func TestStorageEndpointsNeedAuthAndAdminForBuckets(t *testing.T) {
	up, reqs, _ := fakeStorage(t)
	h := serverWith(t, func(c *config.Config) {
		c.StorageURL = up.URL + "/storage/v1"
		c.AdminUserIDs = []string{"22222222-2222-2222-2222-222222222222"}
	}).Handler()

	if rec := do(h, httptest.NewRequest("POST", "/api/v1/storage/objects/docs/list", strings.NewReader(`{}`))); rec.Code != 401 {
		t.Fatalf("no credentials: %d", rec.Code)
	}
	user := sign(t, "11111111-1111-1111-1111-111111111111", "authenticated")
	req := httptest.NewRequest("GET", "/api/v1/storage/buckets", nil)
	req.Header.Set("Authorization", "Bearer "+user)
	if rec := do(h, req); rec.Code != 403 {
		t.Fatalf("non-admin: %d", rec.Code)
	}

	// service_role keys have no `sub` and must be accepted as admin
	svc, _ := jwtNoSub(t, "service_role")
	req = httptest.NewRequest("GET", "/api/v1/storage/buckets", nil)
	req.Header.Set("Authorization", "Bearer "+svc)
	rec := do(h, req)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "other-app") || !strings.Contains(rec.Body.String(), "saas-test-docs") {
		t.Fatalf("admin list should only show this app's buckets: %d %s", rec.Code, rec.Body)
	}
	if got := (*reqs)[len(*reqs)-1].Header.Get("Authorization"); got != "Bearer service-key" {
		t.Errorf("bucket admin must use the service key, got %q", got)
	}

	// anon (no sub, not service_role) is rejected
	anon, _ := jwtNoSub(t, "anon")
	req = httptest.NewRequest("GET", "/api/v1/storage/buckets", nil)
	req.Header.Set("Authorization", "Bearer "+anon)
	if rec := do(h, req); rec.Code != 401 {
		t.Fatalf("anon: %d", rec.Code)
	}
}

func jwtNoSub(t *testing.T, role string) (string, error) {
	t.Helper()
	return signClaims(t, map[string]any{"role": role, "exp": time.Now().Add(time.Hour).Unix()}), nil
}

func signClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// --- billing ------------------------------------------------------------------------

func hmacHex(secret string, parts ...string) string {
	m := hmac.New(sha256.New, []byte(secret))
	for _, p := range parts {
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

func TestStripeSignatureVerification(t *testing.T) {
	body := []byte(`{"id":"evt_1"}`)
	now := time.Unix(1_700_000_000, 0)
	header := fmt.Sprintf("t=%d,v1=%s", now.Unix(), hmacHex("whsec_x", fmt.Sprint(now.Unix()), ".", string(body)))
	if err := verifyStripeSignature(body, header, "whsec_x", now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := verifyStripeSignature(body, header, "whsec_y", now); err == nil || err.Error() != "signature mismatch" {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := verifyStripeSignature(body, header, "whsec_x", now.Add(301*time.Second)); err == nil || err.Error() != "timestamp outside tolerance" {
		t.Fatalf("stale: %v", err)
	}
	if err := verifyStripeSignature([]byte("tampered"), header, "whsec_x", now); err == nil {
		t.Fatal("tampered body must fail")
	}
}

func TestLemonSqueezySignatureVerification(t *testing.T) {
	body := []byte(`{"meta":{}}`)
	sig := hmacHex("ls", string(body))
	if err := verifyLemonSqueezySignature(body, sig, "ls"); err != nil {
		t.Fatal(err)
	}
	if verifyLemonSqueezySignature(body, sig, "other") == nil || verifyLemonSqueezySignature(body, "zz", "ls") == nil {
		t.Fatal("bad secret / malformed signature must fail")
	}
}

func mustEvent(t *testing.T, raw string) map[string]any {
	t.Helper()
	ev, err := decodeEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestParseStripeSubscriptionEvents(t *testing.T) {
	plans := map[string]string{"price_pro": "pro"}
	u := parseStripeEvent(mustEvent(t, fmt.Sprintf(`{
		"type":"customer.subscription.updated",
		"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active",
		  "metadata":{"workspace_id":"%s"},
		  "items":{"data":[{"price":{"id":"price_pro"},"current_period_end":1800000000}]}}}}`, strings.ToUpper(ws1))), plans)
	if u == nil || u.WorkspaceID != ws1 || u.Plan != "pro" || u.Status != "active" || u.PeriodEnd == nil || u.PeriodEnd.Unix() != 1_800_000_000 {
		t.Fatalf("%+v", u)
	}
	del := parseStripeEvent(mustEvent(t, `{"type":"customer.subscription.deleted","data":{"object":{"id":"sub_1","status":"active"}}}`), plans)
	if del == nil || del.Status != "canceled" || !isTerminalStatus(del.Status) {
		t.Fatalf("%+v", del)
	}
	co := parseStripeEvent(mustEvent(t, `{"type":"checkout.session.completed","data":{"object":{"client_reference_id":"`+ws1+`","customer":"cus_9","subscription":"sub_9"}}}`), plans)
	if co == nil || co.WorkspaceID != ws1 || co.SubscriptionID != "sub_9" {
		t.Fatalf("%+v", co)
	}
	if parseStripeEvent(mustEvent(t, `{"type":"invoice.paid","data":{"object":{}}}`), plans) != nil {
		t.Fatal("unrelated events are ignored")
	}
}

func TestParseLemonSqueezyEvents(t *testing.T) {
	plans := map[string]string{"42": "team"}
	u := parseLemonSqueezyEvent(mustEvent(t, `{
		"meta":{"event_name":"subscription_created","custom_data":{"workspace_id":"`+ws1+`"}},
		"data":{"id":"99","attributes":{"status":"active","variant_id":42,"customer_id":7,"renews_at":"2030-01-01T00:00:00.000000Z"}}}`), plans)
	if u == nil || u.Plan != "team" || u.SubscriptionID != "99" || u.CustomerID != "7" || u.PeriodEnd == nil || u.PeriodEnd.Year() != 2030 {
		t.Fatalf("%+v", u)
	}
	if parseLemonSqueezyEvent(mustEvent(t, `{"meta":{"event_name":"subscription_payment_success"},"data":{"attributes":{}}}`), plans) != nil {
		t.Fatal("payment events are ignored")
	}
	exp := parseLemonSqueezyEvent(mustEvent(t, `{"meta":{"event_name":"subscription_expired"},"data":{"id":"1","attributes":{"status":"active"}}}`), plans)
	if exp == nil || exp.Status != "expired" {
		t.Fatalf("%+v", exp)
	}
}

func TestWebhookRejectsBadSignatureAndMissingSecret(t *testing.T) {
	h := serverWith(t, func(c *config.Config) { c.StripeWebhookSecret = "whsec_x" }).Handler()
	req := httptest.NewRequest("POST", "/webhooks/stripe", strings.NewReader(`{"id":"evt"}`))
	req.Header.Set("Stripe-Signature", "t=1,v1=00")
	if rec := do(h, req); rec.Code != 400 {
		t.Fatalf("bad signature: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, httptest.NewRequest("POST", "/webhooks/lemonsqueezy", strings.NewReader(`{}`))); rec.Code != 503 {
		t.Fatalf("unconfigured provider: %d", rec.Code)
	}
}

// --- vector --------------------------------------------------------------------------

func TestVectorHelpers(t *testing.T) {
	if got := vectorLiteral([]float32{1, 0.5, -2.25}); got != "[1,0.5,-2.25]" {
		t.Fatalf("got %s", got)
	}
	srv := serverWith(t, nil)
	if srv.checkDims([]float32{1, 2, 3}) != nil || srv.checkDims([]float32{1, 2}) == nil {
		t.Fatal("dimension check")
	}
	if !isUUID(ws1) || isUUID("nope") || isUUID(strings.Repeat("g", 36)) {
		t.Fatal("isUUID")
	}
}

func TestVectorEndpointsRequireCredentialsAndMatchingWorkspace(t *testing.T) {
	h := serverWith(t, nil).Handler()
	req := httptest.NewRequest("POST", "/api/v1/workspaces/"+ws1+"/embeddings/search", strings.NewReader(`{"query":"x"}`))
	if rec := do(h, req); rec.Code != 401 {
		t.Fatalf("no credentials: %d", rec.Code)
	}
	user := sign(t, "11111111-1111-1111-1111-111111111111", "authenticated")
	req = httptest.NewRequest("POST", "/api/v1/workspaces/not-a-uuid/embeddings/search", strings.NewReader(`{"query":"x"}`))
	req.Header.Set("Authorization", "Bearer "+user)
	if rec := do(h, req); rec.Code != 400 {
		t.Fatalf("bad workspace id: %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "/api/v1/workspaces/"+ws1+"/embeddings/search", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+user)
	if rec := do(h, req); rec.Code != 400 || !strings.Contains(rec.Body.String(), "embedding") {
		t.Fatalf("neither embedding nor query: %d %s", rec.Code, rec.Body)
	}
}

func TestEmbedTextsCallsOpenAICompatibleProvider(t *testing.T) {
	var gotAuth, gotModel string
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var in struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		gotModel = in.Model
		// answer out of order to prove the client re-sorts by index
		_, _ = w.Write([]byte(`{"data":[{"index":1,"embedding":[4,5,6]},{"index":0,"embedding":[1,2,3]}]}`))
	}))
	defer prov.Close()
	srv := serverWith(t, func(c *config.Config) {
		c.EmbeddingAPIURL, c.EmbeddingAPIKey, c.EmbeddingModel = prov.URL, "k", "m1"
	})
	vecs, e := srv.embedTexts(context.Background(), []string{"a", "b"})
	if e != nil || len(vecs) != 2 || vecs[0][0] != 1 || vecs[1][0] != 4 {
		t.Fatalf("%v %v", vecs, e)
	}
	if gotAuth != "Bearer k" || gotModel != "m1" {
		t.Fatalf("auth=%q model=%q", gotAuth, gotModel)
	}
}

// --- rate limiting & metrics ----------------------------------------------------------

func TestSharedRateLimiterFailsOverToLocalBucket(t *testing.T) {
	srv := serverWith(t, func(c *config.Config) { c.RateLimitBackend = "postgres" })
	h := srv.Handler()
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "11111111-1111-1111-1111-111111111111", "authenticated"))
	// database is unreachable: the request must still succeed via the local bucket
	if rec := do(h, req); rec.Code != 200 {
		t.Fatalf("limiter outage must not become an API outage, got %d %s", rec.Code, rec.Body)
	}
	if srv.metrics.rateLimitFallbacks.Load() == 0 {
		t.Fatal("fallback not counted")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := serverWith(t, func(c *config.Config) { c.MetricsToken = "tok" })
	h := srv.Handler()
	do(h, httptest.NewRequest("GET", "/health", nil))
	if rec := do(h, httptest.NewRequest("GET", "/metrics", nil)); rec.Code != 401 {
		t.Fatalf("token required: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := do(h, req)
	for _, want := range []string{`xbase_http_requests_total{app="saas-test",class="2xx"}`, "xbase_ws_connections", "xbase_db_pool_connections", "xbase_rate_limit_fallbacks_total"} {
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("missing %q in %d\n%s", want, rec.Code, rec.Body)
		}
	}
}

// --- realtime: hub ---------------------------------------------------------------------

func newConn(id uint64) *wsConn {
	return &wsConn{id: id, send: make(chan []byte, 16), rooms: map[string]bool{}, workspaces: map[string]bool{}}
}

func recvJSON(t *testing.T, c *wsConn) map[string]any {
	t.Helper()
	select {
	case b := <-c.send:
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for a message")
		return nil
	}
}

func noMessage(t *testing.T, c *wsConn) {
	t.Helper()
	select {
	case b := <-c.send:
		t.Fatalf("unexpected message: %s", b)
	default:
	}
}

func clusterPair() (a, b *hub, aOut, bOut chan string) {
	a, b = newHub("app"), newHub("app")
	aOut, bOut = make(chan string, 64), make(chan string, 64)
	a.enableCluster(aOut)
	b.enableCluster(bOut)
	return
}

// pump delivers what one replica published to the other, like the NOTIFY round trip.
func pump(t *testing.T, from chan string, to *hub) {
	t.Helper()
	for {
		select {
		case raw := <-from:
			var env envelope
			if err := json.Unmarshal([]byte(raw), &env); err != nil {
				t.Fatal(err)
			}
			to.applyRemote(env)
		default:
			return
		}
	}
}

func TestHubRoomsBroadcastAndPresence(t *testing.T) {
	h := newHub("app")
	a, b := newConn(1), newConn(2)
	h.join("lobby", a, "ua")
	h.join("lobby", b, "ub")

	if !h.broadcast("lobby", a, map[string]any{"type": "broadcast", "payload": 1}) {
		t.Fatal("member broadcast refused")
	}
	if got := recvJSON(t, b); got["payload"] != float64(1) {
		t.Fatalf("%v", got)
	}
	noMessage(t, a) // sender does not receive its own broadcast

	h.track("lobby", a, map[string]any{"status": "online"}, true)
	diff := recvJSON(t, b)
	if diff["type"] != "presence_diff" || diff["joins"].(map[string]any)["1"].(map[string]any)["state"].(map[string]any)["status"] != "online" {
		t.Fatalf("%v", diff)
	}
	snap := h.join("lobby", newConn(3), "uc")
	if snap["1"].(map[string]any)["user_id"] != "ua" {
		t.Fatalf("late joiner snapshot: %v", snap)
	}

	h.leave("lobby", a)
	leave := recvJSON(t, b)
	if leave["leaves"].(map[string]any)["1"].(map[string]any)["state"].(map[string]any)["status"] != "online" {
		t.Fatalf("%v", leave)
	}
	if h.broadcast("lobby", newConn(9), map[string]any{}) {
		t.Fatal("non-members cannot broadcast")
	}
	h.leave("lobby", b)
	if _, rooms := h.stats(); rooms != 1 {
		t.Fatalf("room with one member left should remain, got %d", rooms)
	}
}

func TestHubClusterBroadcastAndPresenceCrossReplicas(t *testing.T) {
	a, b, aOut, bOut := clusterPair()
	ca, cb := newConn(1), newConn(2)
	a.join("lobby", ca, "ua")
	b.join("lobby", cb, "ub")
	pump(t, aOut, b)
	pump(t, bOut, a)

	a.broadcast("lobby", ca, map[string]any{"type": "broadcast", "payload": 42})
	pump(t, aOut, b)
	if got := recvJSON(t, cb); got["payload"] != float64(42) {
		t.Fatalf("%v", got)
	}

	a.track("lobby", ca, map[string]any{"status": "online"}, true)
	pump(t, aOut, b)
	if diff := recvJSON(t, cb); diff["joins"].(map[string]any)["1"] == nil {
		t.Fatalf("%v", diff)
	}
	snap := b.join("lobby", newConn(3), "uc")
	if snap["1"] == nil {
		t.Fatalf("replicated presence missing from late joiner's snapshot: %v", snap)
	}

	a.leave("lobby", ca)
	pump(t, aOut, b)
	if leave := recvJSON(t, cb); leave["leaves"].(map[string]any)["1"] == nil {
		t.Fatalf("%v", leave)
	}
}

func TestHubClusterNewReplicaMemberGetsExistingPresenceViaSync(t *testing.T) {
	a, b, aOut, bOut := clusterPair()
	ca, cb := newConn(1), newConn(2)
	a.join("lobby", ca, "ua")
	a.track("lobby", ca, map[string]any{"n": 1}, true)
	pump(t, aOut, b) // B has no members yet: ignored

	snap := b.join("lobby", cb, "ub")
	if len(snap) != 0 {
		t.Fatalf("nothing replicated yet, got %v", snap)
	}
	pump(t, bOut, a) // A sees the req and answers with a sync
	pump(t, aOut, b)
	diff := recvJSON(t, cb)
	if diff["joins"].(map[string]any)["1"].(map[string]any)["state"].(map[string]any)["n"] != float64(1) {
		t.Fatalf("%v", diff)
	}
}

func TestHubClusterSilentReplicaPresenceExpires(t *testing.T) {
	a, b, aOut, _ := clusterPair()
	ca, cb := newConn(1), newConn(2)
	a.join("lobby", ca, "ua")
	b.join("lobby", cb, "ub")
	a.track("lobby", ca, map[string]any{"x": 1}, true)
	pump(t, aOut, b)
	recvJSON(t, cb) // the join diff

	b.expireRemote(0)
	if leave := recvJSON(t, cb); leave["leaves"].(map[string]any)["1"] == nil {
		t.Fatalf("%v", leave)
	}
}

func TestHubClusterIgnoresOwnAndForeignAppEnvelopes(t *testing.T) {
	a, _, _, _ := clusterPair()
	c := newConn(1)
	a.join("lobby", c, "ua")
	a.applyRemote(envelope{K: "msg", O: a.origin, App: "app", Room: "lobby", Msg: map[string]any{"type": "broadcast"}})
	a.applyRemote(envelope{K: "msg", O: "other", App: "different-app", Room: "lobby", Msg: map[string]any{"type": "broadcast"}})
	noMessage(t, c)
	if roomChannel("saas-app-1") != "xbase_rt_saas_app_1" || len(roomChannel(strings.Repeat("x", 200))) > 63 {
		t.Fatal("channel naming")
	}
}

func TestEnvelopeIsWireCompatibleWithRustBackend(t *testing.T) {
	// Shapes produced by backend/src/realtime.rs (serde tag = "k").
	var env envelope
	raw := `{"k":"sync","o":"abc","app":"app","room":"lobby","presence":{"1":{"user_id":"u","state":{"n":1}}}}`
	if err := json.Unmarshal([]byte(raw), &env); err != nil || env.K != "sync" || env.Presence["1"]["user_id"] != "u" {
		t.Fatalf("%v %+v", err, env)
	}
	out, _ := json.Marshal(envelope{K: "req", O: "o", App: "app", Room: "lobby"})
	if string(out) != `{"k":"req","o":"o","app":"app","room":"lobby"}` {
		t.Fatalf("%s", out)
	}
}

// --- realtime: real WebSocket round trip ---------------------------------------------------

func wsURL(ts *httptest.Server, token string) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?access_token=" + token
}

func readJSON(t *testing.T, ctx context.Context, c *websocket.Conn) map[string]any {
	t.Helper()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}

func sendJSON(t *testing.T, ctx context.Context, c *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestWebSocketRequiresToken(t *testing.T) {
	h := serverWith(t, nil).Handler()
	if rec := do(h, httptest.NewRequest("GET", "/ws", nil)); rec.Code != 401 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(h, httptest.NewRequest("GET", "/ws?access_token=garbage", nil)); rec.Code != 401 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	anon, _ := jwtNoSub(t, "anon")
	if rec := do(h, httptest.NewRequest("GET", "/ws?access_token="+anon, nil)); rec.Code != 401 {
		t.Fatalf("anon (no user) token: %d", rec.Code)
	}
}

func TestWebSocketBroadcastAndPresenceRoundTrip(t *testing.T) {
	srv := serverWith(t, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dial := func(sub string) *websocket.Conn {
		c, _, err := websocket.Dial(ctx, wsURL(ts, sign(t, sub, "authenticated")), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.CloseNow() })
		if hello := readJSON(t, ctx, c); hello["type"] != "connected" || hello["user_id"] != sub {
			t.Fatalf("hello: %v", hello)
		}
		return c
	}
	u1, u2 := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	c1, c2 := dial(u1), dial(u2)

	for _, c := range []*websocket.Conn{c1, c2} {
		sendJSON(t, ctx, c, map[string]any{"type": "join", "room": "lobby"})
		if j := readJSON(t, ctx, c); j["type"] != "joined" || j["room"] != "lobby" {
			t.Fatalf("joined: %v", j)
		}
	}

	sendJSON(t, ctx, c1, map[string]any{"type": "broadcast", "room": "lobby", "event": "cursor", "payload": map[string]any{"x": 1}})
	got := readJSON(t, ctx, c2)
	if got["type"] != "broadcast" || got["event"] != "cursor" || got["from"] != u1 || got["payload"].(map[string]any)["x"] != float64(1) {
		t.Fatalf("broadcast: %v", got)
	}

	sendJSON(t, ctx, c1, map[string]any{"type": "track", "room": "lobby", "state": map[string]any{"status": "online"}})
	if d := readJSON(t, ctx, c2); d["type"] != "presence_diff" {
		t.Fatalf("diff: %v", d)
	}

	sendJSON(t, ctx, c2, map[string]any{"type": "ping"})
	if p := readJSON(t, ctx, c2); p["type"] != "pong" {
		t.Fatalf("pong: %v", p)
	}
	sendJSON(t, ctx, c2, map[string]any{"type": "broadcast", "room": "not-joined", "event": "x"})
	if e := readJSON(t, ctx, c2); e["type"] != "error" {
		t.Fatalf("expected an error for broadcasting to an un-joined room: %v", e)
	}
	sendJSON(t, ctx, c2, map[string]any{"type": "join", "room": "bad room!"})
	if e := readJSON(t, ctx, c2); e["type"] != "error" {
		t.Fatalf("expected an error for an invalid room name: %v", e)
	}

	// closing c1 removes its presence for the others
	_ = c1.Close(websocket.StatusNormalClosure, "bye")
	if d := readJSON(t, ctx, c2); d["type"] != "presence_diff" || len(d["leaves"].(map[string]any)) != 1 {
		t.Fatalf("leave diff: %v", d)
	}
	if conns, _ := srv.hub.stats(); conns < 1 {
		t.Fatalf("connection accounting: %d", conns)
	}
}

func TestClaimsExpiredAndRoomNames(t *testing.T) {
	if !claimsExpired(&auth.Claims{Raw: map[string]any{"exp": float64(1)}}) || claimsExpired(&auth.Claims{Raw: map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())}}) {
		t.Fatal("expiry")
	}
	if !validRoom("workspace:7c9e-1_a.b") || validRoom("") || validRoom("a b") || validRoom(strings.Repeat("a", 129)) {
		t.Fatal("room names")
	}
}
