package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/config"
)

// ------------------------------------------------------------------ REST builders
// The SQL must match backend/src/rest.rs byte for byte (same tests, same strings).

func restCat() *catalog {
	return &catalog{
		schema: "public",
		tables: map[string][]column{
			"todos":    {{"id", "bigint"}, {"title", "text"}, {"done", "boolean"}, {"tags", "text[]"}, {"meta", "jsonb"}, {"author_id", "uuid"}},
			"profiles": {{"id", "uuid"}, {"name", "text"}},
			"comments": {{"id", "bigint"}, {"todo_id", "bigint"}, {"author_id", "uuid"}, {"body", "text"}},
		},
		fks: []foreignKey{
			{Name: "todos_author_fk", Table: "todos", Cols: []string{"author_id"}, FTable: "profiles", FCols: []string{"id"}},
			{Name: "comments_todo_fk", Table: "comments", Cols: []string{"todo_id"}, FTable: "todos", FCols: []string{"id"}},
			{Name: "comments_author_fk", Table: "comments", Cols: []string{"author_id"}, FTable: "profiles", FCols: []string{"id"}},
		},
	}
}

func sel(t *testing.T, q string) (*built, *apiError) {
	t.Helper()
	p, e := parseRestQuery(q)
	if e != nil {
		return nil, e
	}
	return buildSelect(restCat(), "todos", p, 1000)
}

func mustSel(t *testing.T, q string) *built {
	t.Helper()
	b, e := sel(t, q)
	if e != nil {
		t.Fatalf("%s: %v", q, e)
	}
	return b
}

func contains(t *testing.T, sql, want string) {
	t.Helper()
	if !strings.Contains(sql, want) {
		t.Fatalf("SQL\n  %s\nlacks\n  %s", sql, want)
	}
}

func TestRestSelectFiltersOrderPaging(t *testing.T) {
	b := mustSel(t, "select=id,title&done=eq.false&title=ilike.*milk*&order=id.desc.nullslast&limit=20&offset=40")
	contains(t, b.sql, `select "t"."id", "t"."title" from "public"."todos" as t`)
	contains(t, b.sql, `("t"."done" = ($1::text)::boolean)`)
	contains(t, b.sql, `("t"."title"::text ilike $2)`)
	contains(t, b.sql, `order by "t"."id" desc nulls last limit 20 offset 40`)
	if len(b.binds) != 2 || b.binds[0] != "false" || b.binds[1] != "%milk%" {
		t.Fatalf("binds %v", b.binds)
	}
	capped, _ := buildSelect(restCat(), "todos", must(parseRestQuery("limit=999999")), 50)
	contains(t, capped.sql, "limit 50 offset 0")
}

func must[T any](v T, e *apiError) T {
	if e != nil {
		panic(e)
	}
	return v
}

func TestRestInIsNegation(t *testing.T) {
	b := mustSel(t, `id=in.(1,2,"3,4")&meta=is.null&done=not.eq.true`)
	contains(t, b.sql, `"t"."id" = any(($1::text[])::bigint[])`)
	contains(t, b.sql, `"t"."meta" is null`)
	contains(t, b.sql, `(not ("t"."done" = ($2::text)::boolean))`)
	if items := b.binds[0].([]string); len(items) != 3 || items[2] != "3,4" {
		t.Fatalf("in list %v", items)
	}
}

func TestRestLogicalGroups(t *testing.T) {
	b := mustSel(t, `or=(done.eq.true,title.ilike.*urgent*)&id=gt.5`)
	contains(t, b.sql, `where (("t"."done" = ($1::text)::boolean) or ("t"."title"::text ilike $2)) and ("t"."id" > ($3::text)::bigint)`)
	n := mustSel(t, `and=(id.gte.1,or(done.is.true,title.eq."a,b"),not.or(id.eq.9,id.eq.10))`)
	contains(t, n.sql, `(("t"."id" >= ($1::text)::bigint) and (("t"."done" is true) or ("t"."title" = ($2::text)::text)) and (not (("t"."id" = ($3::text)::bigint) or ("t"."id" = ($4::text)::bigint))))`)
	if n.binds[1] != "a,b" {
		t.Fatalf("quoted value %v", n.binds[1])
	}
	neg := mustSel(t, "not.and=(id.eq.1,done.eq.false)")
	contains(t, neg.sql, `where (not (("t"."id" = ($1::text)::bigint) and ("t"."done" = ($2::text)::boolean)))`)
	in := mustSel(t, "or=(id.in.(1,2),title.not.eq.x)")
	contains(t, in.sql, `any(($1::text[])::bigint[])`)
	contains(t, in.sql, `(not ("t"."title" = ($2::text)::text))`)
	for _, bad := range []string{"or=(nope.eq.1)", "or=done.eq.true", "or=(done.eq.true", "or=()", "or=(and(and(and(and(id.eq.1)))))", "not=x"} {
		if _, e := sel(t, bad); e == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRestEmbedding(t *testing.T) {
	b := mustSel(t, "select=id,author:profiles(name),comments(id,body,profiles(name))")
	contains(t, b.sql, `(select to_jsonb(r1) from (select "e1"."name" from "public"."profiles" as "e1" where "e1"."id" = "t"."author_id" limit 1) r1) as "author"`)
	contains(t, b.sql, `(select coalesce(jsonb_agg(to_jsonb(r2)), '[]'::jsonb) from (select "e2"."id", "e2"."body", (select to_jsonb(r3) from (select "e3"."name" from "public"."profiles" as "e3" where "e3"."id" = "e2"."author_id" limit 1) r3) as "profiles" from "public"."comments" as "e2" where "e2"."todo_id" = "t"."id") r2) as "comments"`)
	for _, ok := range []string{"select=id,a:profiles!todos_author_fk(*)", "select=id,a:profiles!author_id(id)", "select=t:title"} {
		if _, e := sel(t, ok); e != nil {
			t.Errorf("%s rejected: %v", ok, e)
		}
	}
	for _, bad := range []string{"select=id,profiles!nope(id)", "select=id,todos(id)", "select=id,nothere(id)", "select=id,profiles(secret)",
		"select=a:b:c(id)", "select=id,comments(id,todos(id,comments(id,todos(id))))", `select=id,profiles"x(id)`, `select=x"y:title`, "select=id::text"} {
		if _, e := sel(t, bad); e == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	c := restCat()
	c.fks = append(c.fks, foreignKey{Name: "todos_reviewer_fk", Table: "todos", Cols: []string{"id"}, FTable: "profiles", FCols: []string{"id"}})
	if _, e := buildSelect(c, "todos", must(parseRestQuery("select=profiles(name)")), 10); e == nil {
		t.Fatal("ambiguous relationship accepted")
	}
	if _, e := buildSelect(c, "todos", must(parseRestQuery("select=profiles!todos_reviewer_fk(name)")), 10); e != nil {
		t.Fatal(e)
	}
}

func TestRestInjectionRejectedOrBound(t *testing.T) {
	for _, bad := range []string{`id"%3Bdrop=eq.1`, "select=id;drop", "order=nope.asc", "order=id.desc;drop", "id=in.(1)&done=is.true;drop", "tags=in.(a)", "id=bogus.1"} {
		if _, e := sel(t, bad); e == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	b := mustSel(t, "title=eq.x'%3B+drop+table+todos;--")
	if strings.Contains(b.sql, "drop table") || b.binds[0] != "x'; drop table todos;--" {
		t.Fatalf("value not bound: %s %v", b.sql, b.binds)
	}
	if qi(`we"ird`) != `"we""ird"` || lit("it's") != "'it''s'" {
		t.Fatal("quoting")
	}
}

func TestRestMutations(t *testing.T) {
	cols := restCat().tables["todos"]
	var body any
	json.Unmarshal([]byte(`[{"title":"a"},{"title":"b","done":true}]`), &body)
	b, e := buildInsert("public", "todos", cols, body, "", false)
	if e != nil {
		t.Fatal(e)
	}
	contains(t, b.sql, `insert into "public"."todos" ("title") select "title" from jsonb_populate_recordset(null::"public"."todos", $1::jsonb)`)
	contains(t, b.sql, `("title", "done") select "title", "done" from jsonb_populate_recordset(null::"public"."todos", $2::jsonb)`)
	if len(b.binds) != 2 {
		t.Fatal("expected 2 groups")
	}
	obj := map[string]any{"id": 1, "title": "x"}
	m, _ := buildInsert("public", "todos", cols, obj, "id", true)
	contains(t, m.sql, `on conflict ("id") do update set "title" = excluded."title"`)
	ig, _ := buildInsert("public", "todos", cols, obj, "id", false)
	contains(t, ig.sql, `on conflict ("id") do nothing`)
	for _, bad := range []any{map[string]any{"nope": 1}, []any{}, 5.0} {
		if _, e := buildInsert("public", "todos", cols, bad, "", false); e == nil {
			t.Errorf("insert %v accepted", bad)
		}
	}
	if _, e := buildInsert("public", "todos", cols, obj, "zzz", true); e == nil {
		t.Error("bad on_conflict accepted")
	}
	if _, e := buildUpdate("public", "todos", cols, map[string]any{"done": true}, &restParams{}); e == nil {
		t.Error("unfiltered PATCH accepted")
	}
	if _, e := buildDelete("public", "todos", cols, &restParams{}); e == nil {
		t.Error("unfiltered DELETE accepted")
	}
	u, _ := buildUpdate("public", "todos", cols, map[string]any{"done": true}, must(parseRestQuery("id=eq.7")))
	contains(t, u.sql, `set "done" = s."done" from jsonb_populate_record`)
	contains(t, u.sql, `where ("t"."id" = ($2::text)::bigint)`)
	g, _ := buildDelete("public", "todos", cols, must(parseRestQuery("or=(id.eq.1,id.eq.2)")))
	contains(t, g.sql, `where (("t"."id" = ($1::text)::bigint) or ("t"."id" = ($2::text)::bigint))`)
}

func TestRestRPC(t *testing.T) {
	f := &function{Args: []fnArg{{"n", "integer", false}, {"tags", "text[]", true}, {"doc", "jsonb", true}}, ReadOnly: true}
	b := buildRPC("public", "add_it", f, map[string]any{"n": 3, "tags": []any{"a"}, "doc": map[string]any{"x": 1}})
	want := `select to_jsonb("public"."add_it"("n" => ($1::jsonb ->> 'n')::integer, "tags" => (case when jsonb_typeof(($1::jsonb -> 'tags')) = 'array' then array(select jsonb_array_elements_text(($1::jsonb -> 'tags'))) end)::text[], "doc" => ($1::jsonb -> 'doc')::jsonb))`
	if b.sql != want {
		t.Fatalf("rpc sql\n got %s\nwant %s", b.sql, want)
	}
	set := *f
	set.ReturnsSet = true
	if !strings.HasPrefix(buildRPC("public", "f", &set, nil).sql, "select coalesce(jsonb_agg(to_jsonb(r))") {
		t.Fatal("setof")
	}
	void := *f
	void.ReturnsVoid = true
	if !strings.HasPrefix(buildRPC("public", "f", &void, nil).sql, "select 'null'::jsonb") {
		t.Fatal("void")
	}
	a := function{Args: []fnArg{{"x", "integer", false}}}
	bb := function{Args: []fnArg{{"x", "integer", false}, {"y", "integer", false}}}
	fns := []function{a, bb}
	if got, _ := pickFunction(fns, []string{"x"}); len(got.Args) != 1 {
		t.Fatal("overload x")
	}
	if got, _ := pickFunction(fns, []string{"x", "y"}); len(got.Args) != 2 {
		t.Fatal("overload x,y")
	}
	for _, keys := range [][]string{{"z"}, {}} {
		if _, e := pickFunction(fns, keys); e == nil {
			t.Errorf("%v matched", keys)
		}
	}
	if _, e := pickFunction([]function{{Args: []fnArg{{"", "integer", false}}}}, nil); e == nil {
		t.Error("unnamed args accepted")
	}
	if _, e := pickFunction([]function{{Args: []fnArg{{"x", "integer", true}}}, {Args: []fnArg{{"x", "text", true}}}}, []string{"x"}); e == nil {
		t.Error("ambiguous overloads accepted")
	}
}

func TestRestRoutesAuthAndSchemaGuard(t *testing.T) {
	s := serverWith(t, func(c *config.Config) { c.RESTEnabled = true; c.RESTSchemas = []string{"public", "xbase"} })
	h := s.Handler()
	if rec := do(h, httptest.NewRequest("GET", "/api/v1/rest/todos", nil)); rec.Code != 401 {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/v1/rest/workspaces", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated"))
	req.Header.Set("Accept-Profile", "xbase")
	if rec := do(h, req); rec.Code != 403 {
		t.Fatalf("internal schema: %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("GET", "/api/v1/rest/bad%22name", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated"))
	if rec := do(h, req); rec.Code != 400 {
		t.Fatalf("bad table: %d", rec.Code)
	}
	off := serverWith(t, nil).Handler()
	req = httptest.NewRequest("GET", "/api/v1/rest/todos", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated"))
	if rec := do(off, req); rec.Code != 404 {
		t.Fatalf("disabled: %d", rec.Code)
	}
}

// ------------------------------------------------------------------ GoTrue proxy

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []map[string]any
}

func fakeUpstream(t *testing.T, status int, reply string, extra http.Header) (*httptest.Server, *seen) {
	t.Helper()
	sn := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		sn.mu.Lock()
		sn.reqs = append(sn.reqs, r)
		sn.body = append(sn.body, m)
		sn.mu.Unlock()
		for k, v := range extra {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, sn
}

func TestGoTrueProxy(t *testing.T) {
	up, sn := fakeUpstream(t, 200, `{"access_token":"a","refresh_token":"r"}`, nil)
	s := serverWith(t, func(c *config.Config) { c.GoTrueURL = up.URL })
	h := s.Handler()

	rec := do(h, httptest.NewRequest("POST", "/api/v1/auth/signup?redirect_to=https://x/cb", strings.NewReader(`{"email":"a@b.c","password":"pw"}`)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("signup: %d %s", rec.Code, rec.Body)
	}
	r0 := sn.reqs[0]
	if r0.URL.Path != "/signup" || r0.URL.Query().Get("redirect_to") != "https://x/cb" || r0.Header.Get("apikey") != "anon-key" {
		t.Fatalf("signup forwarded as %s %v", r0.URL, r0.Header)
	}
	if sn.body[0]["data"].(map[string]any)["signup_app"] != "saas-test" {
		t.Fatalf("signup not tagged: %v", sn.body[0])
	}
	// caller-supplied signup_app is kept
	do(h, httptest.NewRequest("POST", "/api/v1/auth/otp", strings.NewReader(`{"email":"a@b.c","data":{"signup_app":"mine"}}`)))
	if sn.body[1]["data"].(map[string]any)["signup_app"] != "mine" {
		t.Fatal("signup_app overwritten")
	}

	do(h, httptest.NewRequest("POST", "/api/v1/auth/token", strings.NewReader(`{"email":"a@b.c","password":"pw"}`)))
	if q := sn.reqs[2].URL.Query().Get("grant_type"); q != "password" {
		t.Fatalf("grant_type %q", q)
	}
	if rec := do(h, httptest.NewRequest("POST", "/api/v1/auth/refresh", strings.NewReader(`{}`))); rec.Code != 400 {
		t.Fatalf("refresh without token: %d", rec.Code)
	}
	if rec := do(h, httptest.NewRequest("POST", "/api/v1/auth/token", strings.NewReader(`[1]`))); rec.Code != 400 {
		t.Fatalf("non-object body: %d", rec.Code)
	}

	// user endpoints forward the user's own token
	tok := sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated")
	req := httptest.NewRequest("GET", "/api/v1/auth/user", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	do(h, req)
	if got := sn.reqs[len(sn.reqs)-1].Header.Get("Authorization"); got != "Bearer "+tok {
		t.Fatalf("user token not forwarded: %q", got)
	}
	if rec := do(h, httptest.NewRequest("GET", "/api/v1/auth/user", nil)); rec.Code != 401 {
		t.Fatalf("anonymous /auth/user: %d", rec.Code)
	}

	// admin endpoints: service_role only, and they use the service key upstream
	req = httptest.NewRequest("GET", "/api/v1/admin/users?per_page=5000", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if rec := do(h, req); rec.Code != 403 {
		t.Fatalf("non-admin: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/v1/admin/users?per_page=5000", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "", "service_role"))
	do(h, req)
	last := sn.reqs[len(sn.reqs)-1]
	if last.Header.Get("Authorization") != "Bearer service-key" || last.URL.Query().Get("per_page") != "1000" {
		t.Fatalf("admin forwarded as %v %v", last.URL, last.Header)
	}
	req = httptest.NewRequest("DELETE", "/api/v1/admin/users/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "", "service_role"))
	if rec := do(h, req); rec.Code != 400 {
		t.Fatalf("bad admin id: %d", rec.Code)
	}

	// OAuth redirect
	rec = do(h, httptest.NewRequest("GET", "/api/v1/auth/authorize?provider=github&code_challenge=abc", nil))
	loc := rec.Header().Get("Location")
	if rec.Code != 303 || !strings.HasPrefix(loc, "https://api.example.com/auth/v1/authorize?") || !strings.Contains(loc, "code_challenge_method=s256") {
		t.Fatalf("authorize: %d %s", rec.Code, loc)
	}
	if rec := do(h, httptest.NewRequest("GET", "/api/v1/auth/authorize?provider=git%20hub", nil)); rec.Code != 400 {
		t.Fatalf("bad provider: %d", rec.Code)
	}
}

func TestGoTrueErrorsAreRelayed(t *testing.T) {
	up, _ := fakeUpstream(t, 422, `{"msg":"weak password"}`, nil)
	h := serverWith(t, func(c *config.Config) { c.GoTrueURL = up.URL }).Handler()
	rec := do(h, httptest.NewRequest("POST", "/api/v1/auth/signup", strings.NewReader(`{"email":"a@b.c","password":"x"}`)))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "weak password") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	empty, _ := fakeUpstream(t, 204, ``, nil)
	h = serverWith(t, func(c *config.Config) { c.GoTrueURL = empty.URL }).Handler()
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated"))
	if rec := do(h, req); rec.Code != 204 {
		t.Fatalf("logout: %d", rec.Code)
	}
}

// ------------------------------------------------------------------ TUS proxy

func TestTusTokens(t *testing.T) {
	tok := tusToken("s3cret", "app1", "app1-docs", "dXBsb2Fk", "key:k1:ws1")
	if id, e := tusVerify("s3cret", "app1", "app1-docs", tok, "key:k1:ws1"); e != nil || id != "dXBsb2Fk" {
		t.Fatalf("verify: %q %v", id, e)
	}
	for name, args := range map[string][5]string{
		"other caller": {"s3cret", "app1", "app1-docs", tok, "key:k2:ws1"},
		"other bucket": {"s3cret", "app1", "app1-other", tok, "key:k1:ws1"},
		"other secret": {"x", "app1", "app1-docs", tok, "key:k1:ws1"},
		"garbage":      {"s3cret", "app1", "app1-docs", "garbage", "key:k1:ws1"},
		"bad mac":      {"s3cret", "app1", "app1-docs", tok[:len(tok)-1] + "0", "key:k1:ws1"},
	} {
		if _, e := tusVerify(args[0], args[1], args[2], args[3], args[4]); e == nil {
			t.Errorf("%s accepted", name)
		}
	}
	m, e := parseTusMetadata("objectName ZGlyL2EucGRm,contentType YXBwbGljYXRpb24vcGRm,flag")
	if e != nil || m[0] != (kv{"objectName", "dir/a.pdf"}) || m[1].v != "application/pdf" || m[2] != (kv{"flag", ""}) {
		t.Fatalf("metadata %v %v", m, e)
	}
	if _, e := parseTusMetadata("objectName !!!"); e == nil {
		t.Fatal("bad base64 accepted")
	}
}

// The Rust and Go backends must mint identical tokens (any replica verifies any
// URL). The same constant is asserted in backend/src/storage.rs.
const crossTusToken = "ZFhCc2IyRms.98fc9672f942b6a33d6cf9c18defbef1fc981002277e87bdd6193f5132100858"

func TestTusTokenMatchesRust(t *testing.T) {
	if got := tusToken("s3cret", "app1", "app1-docs", "dXBsb2Fk", "key:k1:ws1"); got != crossTusToken {
		t.Fatalf("token %q", got)
	}
}

func TestTusProxyForAPIKeysNeedsDB(t *testing.T) {
	// Without a database the key cannot be authenticated: the proxy must fail closed.
	up, sn := fakeUpstream(t, 201, ``, http.Header{"Location": {"http://storage/upload/resumable/abc"}})
	h := serverWith(t, func(c *config.Config) { c.StorageURL = up.URL }).Handler()
	req := httptest.NewRequest("POST", "/api/v1/storage/tus/docs", nil)
	req.Header.Set(auth.APIKeyHeader, "xb_abcdefabcdef_secret")
	req.Header.Set("Upload-Length", "10")
	req.Header.Set("Upload-Metadata", "objectName "+base64.StdEncoding.EncodeToString([]byte(ws1+"/a.bin")))
	if rec := do(h, req); rec.Code < 400 {
		t.Fatalf("unauthenticated key reached storage: %d", rec.Code)
	}
	if len(sn.reqs) != 0 {
		t.Fatal("storage was called")
	}
}

func TestTusProxyForUsers(t *testing.T) {
	up, sn := fakeUpstream(t, 201, ``, http.Header{"Location": {"http://storage:5000/upload/resumable/VVBMT0FE"}, "Upload-Expires": {"tomorrow"}})
	h := serverWith(t, func(c *config.Config) { c.StorageURL = up.URL }).Handler()
	user := sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated")

	req := httptest.NewRequest("POST", "/api/v1/storage/tus/docs", nil)
	req.Header.Set("Authorization", "Bearer "+user)
	req.Header.Set("Upload-Length", "12")
	req.Header.Set("Upload-Metadata", "objectName "+base64.StdEncoding.EncodeToString([]byte(ws1+"/big.bin"))+",bucketName "+base64.StdEncoding.EncodeToString([]byte("evil")))
	rec := do(h, req)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/v1/storage/tus/docs/") || rec.Header().Get("Tus-Resumable") != "1.0.0" || rec.Header().Get("Upload-Expires") != "tomorrow" {
		t.Fatalf("create headers: %v", rec.Header())
	}
	meta, _ := parseTusMetadata(sn.reqs[0].Header.Get("Upload-Metadata"))
	if meta[0] != (kv{"bucketName", "saas-test-docs"}) || meta[1] != (kv{"objectName", ws1 + "/big.bin"}) || len(meta) != 2 {
		t.Fatalf("forwarded metadata %v", meta)
	}
	if sn.reqs[0].Header.Get("Authorization") != "Bearer "+user {
		t.Fatal("user token not forwarded")
	}

	// PATCH with the issued URL reaches the upstream upload id
	patch := httptest.NewRequest("PATCH", loc, strings.NewReader("hello world!"))
	patch.Header.Set("Authorization", "Bearer "+user)
	patch.Header.Set("Upload-Offset", "0")
	patch.Header.Set("Content-Type", "application/offset+octet-stream")
	if rec := do(h, patch); rec.Code != 201 {
		t.Fatalf("patch: %d", rec.Code)
	}
	last := sn.reqs[len(sn.reqs)-1]
	if last.Method != "PATCH" || last.URL.Path != "/upload/resumable/VVBMT0FE" || last.Header.Get("Upload-Offset") != "0" {
		t.Fatalf("patch forwarded as %s %s %v", last.Method, last.URL, last.Header)
	}

	// another user cannot use the URL
	other := httptest.NewRequest("HEAD", loc, nil)
	other.Header.Set("Authorization", "Bearer "+sign(t, "11111111-1111-1111-1111-111111111111", "authenticated"))
	if rec := do(h, other); rec.Code != 403 {
		t.Fatalf("other user: %d", rec.Code)
	}
	// missing metadata / length
	bad := httptest.NewRequest("POST", "/api/v1/storage/tus/docs", nil)
	bad.Header.Set("Authorization", "Bearer "+user)
	if rec := do(h, bad); rec.Code != 400 {
		t.Fatalf("no Upload-Length: %d", rec.Code)
	}
}

// ------------------------------------------------------------------ keys, jobs, routes

func TestGeneratedKeysAndScopes(t *testing.T) {
	k, prefix := generateKey()
	if auth.APIKeyPrefix(k) != prefix || len(auth.HashAPIKey(k)) != 64 {
		t.Fatalf("key %q prefix %q", k, prefix)
	}
	if k2, _ := generateKey(); k2 == k {
		t.Fatal("keys repeat")
	}
	if s, e := validateScopes(nil); e != nil || s[0] != "workspace:read" {
		t.Fatal("default scope")
	}
	if _, e := validateScopes([]string{"rest:read", "storage:write"}); e != nil {
		t.Fatal(e)
	}
	if _, e := validateScopes([]string{"admin"}); e == nil {
		t.Fatal("unknown scope accepted")
	}
	if len(generateInviteToken()) != 43 {
		t.Fatal("invite token length")
	}
}

func TestJobBackoff(t *testing.T) {
	if backoffSecs(1) != 2 || backoffSecs(5) != 32 || backoffSecs(50) != 3600 || backoffSecs(-3) != 1 {
		t.Fatal("backoff")
	}
	q := newJobQueue()
	q.notify()
	q.notify() // never blocks
	select {
	case <-q.wake:
	default:
		t.Fatal("no wake-up")
	}
}

func TestTagSignup(t *testing.T) {
	if tagSignup(map[string]any{}, "a")["data"].(map[string]any)["signup_app"] != "a" {
		t.Fatal("not tagged")
	}
	if tagSignup(map[string]any{"data": map[string]any{"signup_app": "b"}}, "a")["data"].(map[string]any)["signup_app"] != "b" {
		t.Fatal("overwritten")
	}
}

func TestNewRoutesRequireAuth(t *testing.T) {
	h := serverWith(t, nil).Handler()
	for _, rt := range [][2]string{
		{"PATCH", "/api/v1/workspaces/" + ws1}, {"DELETE", "/api/v1/workspaces/" + ws1},
		{"GET", "/api/v1/workspaces/" + ws1 + "/members"}, {"POST", "/api/v1/workspaces/" + ws1 + "/invitations"},
		{"POST", "/api/v1/invitations/accept"}, {"GET", "/api/v1/workspaces/" + ws1 + "/api-keys"},
		{"POST", "/api/v1/workspaces/" + ws1 + "/api-keys"}, {"POST", "/api/v1/workspaces/" + ws1 + "/embeddings/reindex"},
		{"GET", "/api/v1/tenants/saas-test"}, {"GET", "/api/v1/workspaces/" + ws1},
	} {
		if rec := do(h, httptest.NewRequest(rt[0], rt[1], strings.NewReader(`{}`))); rec.Code != 401 {
			t.Errorf("%s %s: %d", rt[0], rt[1], rec.Code)
		}
	}
	// path UUIDs are validated before touching the database
	req := httptest.NewRequest("GET", "/api/v1/workspaces/nope/members", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, "4b5f3a52-1e0e-4f3c-9d1a-2a6f6c0c2b11", "authenticated"))
	if rec := do(h, req); rec.Code != 400 {
		t.Fatalf("bad uuid: %d", rec.Code)
	}
	// whoami without a key
	if rec := do(h, httptest.NewRequest("GET", "/api/v1/server/whoami", nil)); rec.Code != 400 {
		t.Fatalf("whoami: %d", rec.Code)
	}
}
