package httpapi

// PostgREST-style generic CRUD — a port of backend/src/rest.rs with the same
// routes, query dialect, SQL shape and safety rules:
//
//	GET    /api/v1/rest/{table}?select=id,author:profiles(name)&done=eq.false&or=(a.eq.1,b.gt.2)&order=id.desc&limit=20
//	POST   /api/v1/rest/{table}   object or array (Prefer: resolution=merge-duplicates + ?on_conflict=id)
//	PATCH  /api/v1/rest/{table}?id=eq.7   (a filter is mandatory)
//	DELETE /api/v1/rest/{table}?id=eq.7   (a filter is mandatory)
//	POST   /api/v1/rest/rpc/{function}    {"named": "args"}
//
// Identifiers only ever come from the catalog and are quoted; values are bound
// (`($n::text)::<type>`). Every request runs in an RLS transaction: users as
// themselves, API keys (explicit rest:read / rest:write scopes) as `authenticated`
// with no user id and xbase.request_workspace_id() set (migration 0006).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/festomanolo/xbase/go-backend/internal/db"
)

var deniedSchemas = []string{
	"xbase", "auth", "storage", "extensions", "vault", "graphql", "graphql_public", "realtime",
	"pgsodium", "pgsodium_masks", "supabase_functions", "supabase_migrations", "net", "cron",
	"pgbouncer", "information_schema", "public_internal",
}

const (
	restSchemaTTL   = 60 * time.Second
	restMaxBodyRows = 1000
	restMaxRows     = 1000
	maxEmbedDepth   = 3
	maxGroupDepth   = 4
)

func (s *Server) restRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/rest/rpc/{function}", s.restRPC)
	mux.HandleFunc("GET /api/v1/rest/{table}", s.restSelect)
	mux.HandleFunc("POST /api/v1/rest/{table}", s.restInsert)
	mux.HandleFunc("PATCH /api/v1/rest/{table}", s.restUpdate)
	mux.HandleFunc("DELETE /api/v1/rest/{table}", s.restDelete)
}

// --- catalog ------------------------------------------------------------------------

type column struct{ Name, Type string }

type foreignKey struct {
	Name, Table, FTable string
	Cols, FCols         []string
}

type fnArg struct {
	Name, Type string
	HasDefault bool
}

type function struct {
	Args                                          []fnArg
	ReturnsSet, ReturnsRow, ReturnsVoid, ReadOnly bool
	Variadic                                      bool
}

type cached[T any] struct {
	at time.Time
	v  T
}

type restCatalog struct {
	mu        sync.Mutex
	columns   map[string]cached[[]column]
	fks       map[string]cached[[]foreignKey]
	functions map[string]cached[[]function]
}

func newRestCatalog() *restCatalog {
	return &restCatalog{columns: map[string]cached[[]column]{}, fks: map[string]cached[[]foreignKey]{}, functions: map[string]cached[[]function]{}}
}

func cacheGet[T any](c *restCatalog, m map[string]cached[T], key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := m[key]
	if ok && time.Since(e.at) < restSchemaTTL {
		return e.v, true
	}
	var zero T
	return zero, false
}

func cachePut[T any](c *restCatalog, m map[string]cached[T], key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(m) > 512 {
		clear(m)
	}
	m[key] = cached[T]{time.Now(), v}
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (c *restCatalog) loadColumns(ctx context.Context, q querier, schema, table string) ([]column, error) {
	key := schema + "." + table
	if v, ok := cacheGet(c, c.columns, key); ok {
		return v, nil
	}
	rows, err := q.Query(ctx, `select a.attname::text, format_type(a.atttypid, a.atttypmod)
		  from pg_attribute a
		  join pg_class c on c.oid = a.attrelid
		  join pg_namespace n on n.oid = c.relnamespace
		 where n.nspname = $1 and c.relname = $2
		   and c.relkind in ('r', 'p', 'v', 'm', 'f')
		   and a.attnum > 0 and not a.attisdropped
		 order by a.attnum`, schema, table)
	if err != nil {
		return nil, err
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (column, error) {
		var col column
		return col, r.Scan(&col.Name, &col.Type)
	})
	if err != nil {
		return nil, err
	}
	if len(cols) > 0 { // unknown tables are not cached, so random names cannot grow the map
		cachePut(c, c.columns, key, cols)
	}
	return cols, nil
}

func (c *restCatalog) loadForeignKeys(ctx context.Context, q querier, schema, table string) ([]foreignKey, error) {
	key := schema + "." + table
	if v, ok := cacheGet(c, c.fks, key); ok {
		return v, nil
	}
	rows, err := q.Query(ctx, `select con.conname::text, cl.relname::text,
		       array(select a.attname::text from unnest(con.conkey) with ordinality k(n, i)
		             join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.n order by k.i),
		       fcl.relname::text,
		       array(select a.attname::text from unnest(con.confkey) with ordinality k(n, i)
		             join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.n order by k.i)
		  from pg_constraint con
		  join pg_class cl on cl.oid = con.conrelid
		  join pg_namespace n on n.oid = cl.relnamespace
		  join pg_class fcl on fcl.oid = con.confrelid
		  join pg_namespace fn on fn.oid = fcl.relnamespace
		 where con.contype = 'f' and n.nspname = $1 and fn.nspname = $1
		   and (cl.relname = $2 or fcl.relname = $2)
		 order by con.conname`, schema, table)
	if err != nil {
		return nil, err
	}
	fks, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (foreignKey, error) {
		var fk foreignKey
		return fk, r.Scan(&fk.Name, &fk.Table, &fk.Cols, &fk.FTable, &fk.FCols)
	})
	if err != nil {
		return nil, err
	}
	cachePut(c, c.fks, key, fks)
	return fks, nil
}

func (c *restCatalog) loadFunctions(ctx context.Context, q querier, schema, name string) ([]function, error) {
	key := schema + "." + name
	if v, ok := cacheGet(c, c.functions, key); ok {
		return v, nil
	}
	rows, err := q.Query(ctx, `select p.proretset, t.typtype::text, t.typname::text, p.provolatile::text,
		       coalesce('v' = any(p.proargmodes::text[]), false), p.pronargdefaults,
		       array(select coalesce((p.proargnames)[o.i], '') from unnest(coalesce(p.proallargtypes, p.proargtypes::oid[]))
		             with ordinality o(t, i)
		             where coalesce((p.proargmodes::text[])[o.i], 'i') in ('i', 'b', 'v') order by o.i),
		       array(select format_type(o.t, null) from unnest(coalesce(p.proallargtypes, p.proargtypes::oid[]))
		             with ordinality o(t, i)
		             where coalesce((p.proargmodes::text[])[o.i], 'i') in ('i', 'b', 'v') order by o.i)
		  from pg_proc p
		  join pg_namespace n on n.oid = p.pronamespace
		  join pg_type t on t.oid = p.prorettype
		 where n.nspname = $1 and p.proname = $2 and p.prokind = 'f'`, schema, name)
	if err != nil {
		return nil, err
	}
	fns, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (function, error) {
		var (
			f                   function
			typtype, typname, v string
			ndefaults           int16
			names, types        []string
		)
		if err := r.Scan(&f.ReturnsSet, &typtype, &typname, &v, &f.Variadic, &ndefaults, &names, &types); err != nil {
			return f, err
		}
		first := len(names) - int(max(ndefaults, 0))
		for i := range names {
			f.Args = append(f.Args, fnArg{Name: names[i], Type: types[i], HasDefault: i >= first})
		}
		f.ReturnsRow = typtype == "c" || typname == "record"
		f.ReturnsVoid = typname == "void"
		f.ReadOnly = v == "s" || v == "i"
		return f, nil
	})
	if err != nil {
		return nil, err
	}
	if len(fns) > 0 {
		cachePut(c, c.functions, key, fns)
	}
	return fns, nil
}

// catalog is everything one query may reference, loaded before SQL is built.
type catalog struct {
	schema string
	tables map[string][]column
	fks    []foreignKey
}

func (c *catalog) columns(table string) ([]column, *apiError) {
	cols, ok := c.tables[table]
	if !ok {
		return nil, errBadRequest("Unknown table '%s'", table)
	}
	return cols, nil
}

// --- query model --------------------------------------------------------------------

// bind is a positional parameter: string, []string or a JSON document.
type bind any

type jsonBind struct{ v any }

type cond struct {
	leaf     bool
	col      string
	spec     string
	and      bool
	negate   bool
	children []cond
}

type restParams struct {
	selectSpec, order, onConflict string
	hasSelect                     bool
	limit, offset                 *int64
	filters                       []cond
}

func qi(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }

func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func isIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// splitTop splits on sep outside parentheses and double quotes.
func splitTop(s string, sep rune) ([]string, *apiError) {
	var out []string
	var cur strings.Builder
	depth, quoted := 0, false
	for _, ch := range s {
		switch {
		case ch == '"':
			quoted = !quoted
			cur.WriteRune(ch)
		case ch == '(' && !quoted:
			depth++
			cur.WriteRune(ch)
		case ch == ')' && !quoted:
			depth--
			if depth < 0 {
				return nil, errBadRequest("Unbalanced parentheses")
			}
			cur.WriteRune(ch)
		case ch == sep && depth == 0 && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
	}
	if depth != 0 || quoted {
		return nil, errBadRequest("Unbalanced parentheses or quotes")
	}
	return append(out, cur.String()), nil
}

func unquoteValue(spec string) string {
	op, value, ok := strings.Cut(spec, ".")
	if !ok {
		return spec
	}
	if op == "not" {
		op2, v, ok := strings.Cut(value, ".")
		if !ok {
			return spec
		}
		op, value = "not."+op2, v
	}
	if strings.HasSuffix(op, "in") {
		return op + "." + value
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return op + "." + value
}

func parseGroup(and, negate bool, body string, depth int) (cond, *apiError) {
	if depth > maxGroupDepth {
		return cond{}, errBadRequest("Logical groups nest at most 4 levels")
	}
	if len(body) < 2 || body[0] != '(' || body[len(body)-1] != ')' {
		return cond{}, errBadRequest("or=/and= take a parenthesised list, e.g. or=(a.eq.1,b.eq.2)")
	}
	parts, e := splitTop(body[1:len(body)-1], ',')
	if e != nil {
		return cond{}, e
	}
	g := cond{and: and, negate: negate}
	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		neg, rest := false, item
		if r, ok := strings.CutPrefix(item, "not."); ok && (strings.HasPrefix(r, "or(") || strings.HasPrefix(r, "and(")) {
			neg, rest = true, r
		}
		switch {
		case strings.HasPrefix(rest, "or("):
			c, e := parseGroup(false, neg, rest[2:], depth+1)
			if e != nil {
				return cond{}, e
			}
			g.children = append(g.children, c)
		case strings.HasPrefix(rest, "and("):
			c, e := parseGroup(true, neg, rest[3:], depth+1)
			if e != nil {
				return cond{}, e
			}
			g.children = append(g.children, c)
		default:
			col, spec, ok := strings.Cut(item, ".")
			if !ok || item == "" {
				return cond{}, errBadRequest("Group item '%s' must look like column.op.value", item)
			}
			g.children = append(g.children, cond{leaf: true, col: col, spec: unquoteValue(spec)})
		}
	}
	if len(g.children) == 0 || (len(g.children) == 1 && g.children[0].leaf && g.children[0].col == "") {
		return cond{}, errBadRequest("Empty logical group")
	}
	return g, nil
}

// parseRestQuery keeps parameter order (filters bind in the order given).
func parseRestQuery(raw string) (*restParams, *apiError) {
	p := &restParams{}
	if raw == "" {
		return p, nil
	}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return nil, errBadRequest("Malformed query string")
		}
		switch k {
		case "select":
			p.selectSpec, p.hasSelect = v, true
		case "order":
			p.order = v
		case "limit", "offset":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, errBadRequest("%s must be an integer", k)
			}
			if k == "limit" {
				p.limit = &n
			} else {
				p.offset = &n
			}
		case "on_conflict":
			p.onConflict = v
		case "or", "and", "not.or", "not.and":
			g, e := parseGroup(strings.HasSuffix(k, "and"), strings.HasPrefix(k, "not."), v, 1)
			if e != nil {
				return nil, e
			}
			p.filters = append(p.filters, g)
		case "not":
			return nil, errBadRequest("use not.or=(...) / not.and=(...) or col=not.op.value")
		default:
			p.filters = append(p.filters, cond{leaf: true, col: k, spec: v})
		}
	}
	return p, nil
}

func findCol(cols []column, name string) (column, *apiError) {
	for _, c := range cols {
		if c.Name == name {
			return c, nil
		}
	}
	return column{}, errBadRequest("Unknown column '%s'", name)
}

func parseInList(v string) ([]string, *apiError) {
	if len(v) < 2 || v[0] != '(' || v[len(v)-1] != ')' {
		return nil, errBadRequest("in.(...) requires a parenthesised list")
	}
	var items []string
	var cur strings.Builder
	quoted := false
	for _, ch := range v[1 : len(v)-1] {
		switch {
		case ch == '"':
			quoted = !quoted
		case ch == ',' && !quoted:
			items = append(items, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
	}
	items = append(items, cur.String())
	if len(items) > 1000 {
		return nil, errBadRequest("in.(...) accepts at most 1000 items")
	}
	return items, nil
}

var cmpOps = map[string]string{"eq": "=", "neq": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}

func buildLeaf(cols []column, name, spec, alias string, first int, binds *[]bind) (string, *apiError) {
	col, e := findCol(cols, name)
	if e != nil {
		return "", e
	}
	lhs := qi(alias) + "." + qi(col.Name)
	negate := false
	if r, ok := strings.CutPrefix(spec, "not."); ok {
		negate, spec = true, r
	}
	op, value, ok := strings.Cut(spec, ".")
	if !ok {
		return "", errBadRequest("Filter on '%s' must look like op.value", name)
	}
	n := first + len(*binds)
	wrap := func(c string) string {
		if negate {
			return "(not (" + c + "))"
		}
		return "(" + c + ")"
	}
	switch op {
	case "is":
		var l string
		switch strings.ToLower(value) {
		case "null", "true", "false", "unknown":
			l = strings.ToLower(value)
		default:
			return "", errBadRequest("is.<null|true|false|unknown>")
		}
		not := ""
		if negate {
			not = "not "
		}
		return fmt.Sprintf("(%s is %s%s)", lhs, not, l), nil
	case "in":
		if strings.HasSuffix(col.Type, "]") {
			return "", errBadRequest("in.(...) is not supported on array column '%s'", name)
		}
		items, e := parseInList(value)
		if e != nil {
			return "", e
		}
		*binds = append(*binds, items)
		return wrap(fmt.Sprintf("%s = any(($%d::text[])::%s[])", lhs, n, col.Type)), nil
	case "like", "ilike":
		*binds = append(*binds, strings.ReplaceAll(value, "*", "%"))
		return wrap(fmt.Sprintf("%s::text %s $%d", lhs, op, n)), nil
	}
	if sym, ok := cmpOps[op]; ok {
		*binds = append(*binds, value)
		return wrap(fmt.Sprintf("%s %s ($%d::text)::%s", lhs, sym, n, col.Type)), nil
	}
	return "", errBadRequest("Unsupported operator '%s'", op)
}

func buildCond(cols []column, c cond, alias string, first int, binds *[]bind) (string, *apiError) {
	if c.leaf {
		return buildLeaf(cols, c.col, c.spec, alias, first, binds)
	}
	parts := make([]string, 0, len(c.children))
	for _, ch := range c.children {
		p, e := buildCond(cols, ch, alias, first, binds)
		if e != nil {
			return "", e
		}
		parts = append(parts, p)
	}
	sep := " or "
	if c.and {
		sep = " and "
	}
	joined := strings.Join(parts, sep)
	if c.negate {
		return "(not (" + joined + "))", nil
	}
	return "(" + joined + ")", nil
}

func buildFilters(cols []column, filters []cond, alias string, first int) ([]string, []bind, *apiError) {
	var binds []bind
	clauses := make([]string, 0, len(filters))
	for _, f := range filters {
		c, e := buildCond(cols, f, alias, first, &binds)
		if e != nil {
			return nil, nil, e
		}
		clauses = append(clauses, c)
	}
	return clauses, binds, nil
}

func whereSQL(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	return " where " + strings.Join(clauses, " and ")
}

// --- select list + embedding ----------------------------------------------------------

type selectItem struct {
	star        bool
	name, alias string // column, or embedded relation
	embed       bool
	hint        string
	items       []selectItem
}

func parseSelect(spec string, depth int) ([]selectItem, *apiError) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return []selectItem{{star: true}}, nil
	}
	parts, e := splitTop(spec, ',')
	if e != nil {
		return nil, e
	}
	var out []selectItem
	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		if item == "*" {
			out = append(out, selectItem{star: true})
			continue
		}
		if strings.Contains(item, "::") {
			return nil, errBadRequest("select does not support casts")
		}
		alias, rest := "", item
		if a, r, ok := strings.Cut(item, ":"); ok && !strings.Contains(a, "(") {
			alias, rest = strings.TrimSpace(a), strings.TrimSpace(r)
			if !isIdent(alias) {
				return nil, errBadRequest("Invalid alias '%s'", alias)
			}
		}
		if open := strings.IndexByte(rest, '('); open >= 0 {
			if depth >= maxEmbedDepth {
				return nil, errBadRequest("Embedding nests at most 3 levels")
			}
			inner := rest[open:]
			if len(inner) < 2 || inner[len(inner)-1] != ')' {
				return nil, errBadRequest("Malformed embed '%s'", item)
			}
			rel, hint, _ := strings.Cut(rest[:open], "!")
			if !isIdent(rel) || (hint != "" && !isIdent(hint)) || strings.HasSuffix(rest[:open], "!") {
				return nil, errBadRequest("Invalid embed '%s'", item)
			}
			children, e := parseSelect(inner[1:len(inner)-1], depth+1)
			if e != nil {
				return nil, e
			}
			out = append(out, selectItem{embed: true, name: rel, hint: hint, alias: alias, items: children})
			continue
		}
		if strings.ContainsAny(rest, ")!") {
			return nil, errBadRequest("Invalid select item '%s'", item)
		}
		out = append(out, selectItem{name: rest, alias: alias})
	}
	return out, nil
}

func embeddedTables(items []selectItem, parent string, out *[][2]string) {
	for _, it := range items {
		if it.embed {
			*out = append(*out, [2]string{parent, it.name})
			embeddedTables(it.items, it.name, out)
		}
	}
}

func resolveRelationship(cat *catalog, parent, rel, hint string) (foreignKey, bool, *apiError) {
	type match struct {
		fk    foreignKey
		toOne bool
	}
	var found []match
	for _, fk := range cat.fks {
		hintOK := func(cols []string) bool {
			return hint == "" || fk.Name == hint || (len(cols) == 1 && cols[0] == hint)
		}
		if fk.Table == parent && fk.FTable == rel && hintOK(fk.Cols) {
			found = append(found, match{fk, true})
		} else if parent != rel && fk.Table == rel && fk.FTable == parent && hintOK(fk.Cols) {
			found = append(found, match{fk, false})
		}
	}
	switch len(found) {
	case 0:
		return foreignKey{}, false, errBadRequest("No foreign key between '%s' and '%s'", parent, rel)
	case 1:
		return found[0].fk, found[0].toOne, nil
	}
	names := make([]string, len(found))
	for i, f := range found {
		names[i] = f.fk.Name
	}
	return foreignKey{}, false, errBadRequest("More than one relationship between '%s' and '%s'; disambiguate with %s!<constraint>(...), one of: %s",
		parent, rel, rel, strings.Join(names, ", "))
}

func buildSelectList(cat *catalog, table, alias string, items []selectItem, counter *int) (string, *apiError) {
	cols, e := cat.columns(table)
	if e != nil {
		return "", e
	}
	var parts []string
	for _, it := range items {
		switch {
		case it.star:
			for _, c := range cols {
				parts = append(parts, qi(alias)+"."+qi(c.Name))
			}
		case !it.embed:
			c, e := findCol(cols, it.name)
			if e != nil {
				return "", e
			}
			expr := qi(alias) + "." + qi(c.Name)
			if it.alias != "" {
				expr += " as " + qi(it.alias)
			}
			parts = append(parts, expr)
		default:
			fk, toOne, e := resolveRelationship(cat, table, it.name, it.hint)
			if e != nil {
				return "", e
			}
			*counter++
			inner, row := fmt.Sprintf("e%d", *counter), fmt.Sprintf("r%d", *counter)
			sel, e := buildSelectList(cat, it.name, inner, it.items, counter)
			if e != nil {
				return "", e
			}
			target := qi(cat.schema) + "." + qi(it.name)
			on := func(relCols, parentCols []string) string {
				conds := make([]string, len(relCols))
				for i := range relCols {
					conds[i] = qi(inner) + "." + qi(relCols[i]) + " = " + qi(alias) + "." + qi(parentCols[i])
				}
				return strings.Join(conds, " and ")
			}
			name := it.name
			if it.alias != "" {
				name = it.alias
			}
			if toOne {
				parts = append(parts, fmt.Sprintf("(select to_jsonb(%s) from (select %s from %s as %s where %s limit 1) %s) as %s",
					row, sel, target, qi(inner), on(fk.FCols, fk.Cols), row, qi(name)))
			} else {
				parts = append(parts, fmt.Sprintf("(select coalesce(jsonb_agg(to_jsonb(%s)), '[]'::jsonb) from (select %s from %s as %s where %s) %s) as %s",
					row, sel, target, qi(inner), on(fk.Cols, fk.FCols), row, qi(name)))
			}
		}
	}
	if len(parts) == 0 {
		return "", errBadRequest("Empty select")
	}
	return strings.Join(parts, ", "), nil
}

type built struct {
	sql, countSQL string
	binds         []bind
}

const restAgg = "coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb)"

var orderMods = map[string]string{"asc": " asc", "desc": " desc", "nullsfirst": " nulls first", "nullslast": " nulls last"}

func buildSelect(cat *catalog, table string, p *restParams, maxRows int64) (*built, *apiError) {
	cols, e := cat.columns(table)
	if e != nil {
		return nil, e
	}
	items, e := parseSelect(p.selectSpec, 0)
	if e != nil {
		return nil, e
	}
	counter := 0
	sel, e := buildSelectList(cat, table, "t", items, &counter)
	if e != nil {
		return nil, e
	}
	clauses, binds, e := buildFilters(cols, p.filters, "t", 1)
	if e != nil {
		return nil, e
	}
	filter := whereSQL(clauses)
	order := ""
	if p.order != "" {
		var parts []string
		for _, item := range strings.Split(p.order, ",") {
			segs := strings.Split(strings.TrimSpace(item), ".")
			c, e := findCol(cols, segs[0])
			if e != nil {
				return nil, e
			}
			out := `"t".` + qi(c.Name)
			for _, m := range segs[1:] {
				mod, ok := orderMods[m]
				if !ok {
					return nil, errBadRequest("Unknown order modifier '%s'", m)
				}
				out += mod
			}
			parts = append(parts, out)
		}
		order = " order by " + strings.Join(parts, ", ")
	}
	limit := maxRows
	if p.limit != nil {
		limit = min(max(*p.limit, 0), maxRows)
	}
	var offset int64
	if p.offset != nil {
		offset = max(*p.offset, 0)
	}
	from := qi(cat.schema) + "." + qi(table)
	return &built{
		sql:      fmt.Sprintf("select %s from (select %s from %s as t%s%s limit %d offset %d) r", restAgg, sel, from, filter, order, limit, offset),
		countSQL: fmt.Sprintf("select count(*) from %s as t%s", from, filter),
		binds:    binds,
	}, nil
}

func bodyRows(body any) ([]map[string]any, *apiError) {
	var rows []map[string]any
	switch b := body.(type) {
	case map[string]any:
		rows = []map[string]any{b}
	case []any:
		for _, v := range b {
			o, ok := v.(map[string]any)
			if !ok {
				return nil, errBadRequest("Array items must be JSON objects")
			}
			rows = append(rows, o)
		}
	default:
		return nil, errBadRequest("Body must be a JSON object or array of objects")
	}
	if len(rows) == 0 || len(rows) > restMaxBodyRows {
		return nil, errBadRequest("Body must contain 1-%d rows", restMaxBodyRows)
	}
	return rows, nil
}

// usedColumns returns the table's columns present in row, in table order.
func usedColumns(cols []column, row map[string]any) []column {
	var used []column
	for _, c := range cols {
		if _, ok := row[c.Name]; ok {
			used = append(used, c)
		}
	}
	return used
}

func validateKeys(cols []column, rows []map[string]any) *apiError {
	for _, row := range rows {
		for k := range row {
			if _, e := findCol(cols, k); e != nil {
				return e
			}
		}
	}
	return nil
}

func buildInsert(schema, table string, cols []column, body any, onConflict string, merge bool) (*built, *apiError) {
	rows, e := bodyRows(body)
	if e != nil {
		return nil, e
	}
	if e := validateKeys(cols, rows); e != nil {
		return nil, e
	}
	target := qi(schema) + "." + qi(table)
	var conflictKeys []string
	if onConflict != "" {
		for _, c := range strings.Split(onConflict, ",") {
			col, e := findCol(cols, strings.TrimSpace(c))
			if e != nil {
				return nil, e
			}
			conflictKeys = append(conflictKeys, col.Name)
		}
	}
	type group struct {
		used []column
		rows []any
	}
	var groups []*group
	for _, row := range rows {
		used := usedColumns(cols, row)
		if len(used) == 0 {
			return nil, errBadRequest("Every row must set at least one column")
		}
		var g *group
		for _, cand := range groups {
			if slices.Equal(cand.used, used) {
				g = cand
				break
			}
		}
		if g == nil {
			g = &group{used: used}
			groups = append(groups, g)
		}
		g.rows = append(g.rows, row)
	}
	var ctes, selects []string
	var binds []bind
	for n, g := range groups {
		names := make([]string, len(g.used))
		for i, c := range g.used {
			names[i] = qi(c.Name)
		}
		nameSQL := strings.Join(names, ", ")
		conflict := ""
		if conflictKeys != nil {
			keys := make([]string, len(conflictKeys))
			for i, k := range conflictKeys {
				keys[i] = qi(k)
			}
			var updates []string
			for _, c := range g.used {
				if !slices.Contains(conflictKeys, c.Name) {
					updates = append(updates, fmt.Sprintf("%s = excluded.%s", qi(c.Name), qi(c.Name)))
				}
			}
			if merge && len(updates) > 0 {
				conflict = fmt.Sprintf(" on conflict (%s) do update set %s", strings.Join(keys, ", "), strings.Join(updates, ", "))
			} else {
				conflict = fmt.Sprintf(" on conflict (%s) do nothing", strings.Join(keys, ", "))
			}
		}
		binds = append(binds, jsonBind{g.rows})
		ctes = append(ctes, fmt.Sprintf("i%d as (insert into %s (%s) select %s from jsonb_populate_recordset(null::%s, $%d::jsonb)%s returning *)",
			n, target, nameSQL, nameSQL, target, n+1, conflict))
		selects = append(selects, fmt.Sprintf("select * from i%d", n))
	}
	return &built{
		sql:   fmt.Sprintf("with %s select %s from (%s) r", strings.Join(ctes, ", "), restAgg, strings.Join(selects, " union all ")),
		binds: binds,
	}, nil
}

func buildUpdate(schema, table string, cols []column, body any, p *restParams) (*built, *apiError) {
	if len(p.filters) == 0 {
		return nil, errBadRequest("PATCH requires at least one filter (e.g. ?id=eq.1)")
	}
	obj, ok := body.(map[string]any)
	if !ok {
		return nil, errBadRequest("Body must be a JSON object")
	}
	if e := validateKeys(cols, []map[string]any{obj}); e != nil {
		return nil, e
	}
	used := usedColumns(cols, obj)
	if len(used) == 0 {
		return nil, errBadRequest("Body has no columns")
	}
	sets := make([]string, len(used))
	for i, c := range used {
		sets[i] = fmt.Sprintf("%s = s.%s", qi(c.Name), qi(c.Name))
	}
	clauses, binds, e := buildFilters(cols, p.filters, "t", 2)
	if e != nil {
		return nil, e
	}
	target := qi(schema) + "." + qi(table)
	return &built{
		sql: fmt.Sprintf("with r as (update %s as t set %s from jsonb_populate_record(null::%s, $1::jsonb) as s%s returning t.*) select %s from r",
			target, strings.Join(sets, ", "), target, whereSQL(clauses), restAgg),
		binds: append([]bind{jsonBind{obj}}, binds...),
	}, nil
}

func buildDelete(schema, table string, cols []column, p *restParams) (*built, *apiError) {
	if len(p.filters) == 0 {
		return nil, errBadRequest("DELETE requires at least one filter (e.g. ?id=eq.1)")
	}
	clauses, binds, e := buildFilters(cols, p.filters, "t", 1)
	if e != nil {
		return nil, e
	}
	target := qi(schema) + "." + qi(table)
	return &built{
		sql:   fmt.Sprintf("with r as (delete from %s as t%s returning t.*) select %s from r", target, whereSQL(clauses), restAgg),
		binds: binds,
	}, nil
}

func pickFunction(fns []function, keys []string) (*function, *apiError) {
	var fits []*function
	for i := range fns {
		f := &fns[i]
		ok := !f.Variadic
		for _, a := range f.Args {
			if a.Name == "" || (!a.HasDefault && !slices.Contains(keys, a.Name)) {
				ok = false
			}
		}
		for _, k := range keys {
			if !slices.ContainsFunc(f.Args, func(a fnArg) bool { return a.Name == k }) {
				ok = false
			}
		}
		if ok {
			fits = append(fits, f)
		}
	}
	switch len(fits) {
	case 1:
		return fits[0], nil
	case 0:
		return nil, errBadRequest("No function matches these named arguments (functions need named, non-variadic arguments)")
	}
	return nil, errBadRequest("Ambiguous call: several overloads match these arguments")
}

func buildRPC(schema, name string, f *function, args map[string]any) *built {
	var callArgs []string
	for _, a := range f.Args {
		if _, ok := args[a.Name]; !ok {
			continue
		}
		get := fmt.Sprintf("($1::jsonb -> %s)", lit(a.Name))
		var expr string
		switch {
		case a.Type == "jsonb" || a.Type == "json":
			expr = get + "::" + a.Type
		case strings.HasSuffix(a.Type, "]"):
			expr = fmt.Sprintf("(case when jsonb_typeof(%s) = 'array' then array(select jsonb_array_elements_text(%s)) end)::%s", get, get, a.Type)
		default:
			expr = fmt.Sprintf("($1::jsonb ->> %s)::%s", lit(a.Name), a.Type)
		}
		callArgs = append(callArgs, qi(a.Name)+" => "+expr)
	}
	call := fmt.Sprintf("%s.%s(%s)", qi(schema), qi(name), strings.Join(callArgs, ", "))
	var sql string
	switch {
	case f.ReturnsVoid:
		sql = "select 'null'::jsonb from " + call + " r"
	case f.ReturnsSet:
		sql = "select coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb) from " + call + " r"
	case f.ReturnsRow:
		sql = "select to_jsonb(r) from " + call + " r"
	default:
		sql = "select to_jsonb(" + call + ")"
	}
	return &built{sql: sql, binds: []bind{jsonBind{args}}}
}

// --- execution ---------------------------------------------------------------------------

func (s *Server) restSchema(r *http.Request, profileHeader string) (string, *apiError) {
	if !s.cfg.RESTEnabled {
		return "", &apiError{http.StatusNotFound, "not_found", "The REST API is disabled (set REST_ENABLED=true)"}
	}
	schema := strings.TrimSpace(r.Header.Get(profileHeader))
	if schema == "" {
		if len(s.cfg.RESTSchemas) == 0 {
			return "", &apiError{http.StatusInternalServerError, "internal_error", "no REST schema configured"}
		}
		schema = s.cfg.RESTSchemas[0]
	}
	if !slices.Contains(s.cfg.RESTSchemas, schema) || slices.Contains(deniedSchemas, schema) || strings.HasPrefix(schema, "pg_") {
		return "", errForbidden("Schema '" + schema + "' is not exposed")
	}
	return schema, nil
}

// restPrincipal authenticates the caller; it runs before any catalog access.
func (s *Server) restPrincipal(r *http.Request) (*principal, *apiError) {
	return s.resolvePrincipal(r)
}

// restTx runs fn in the caller's RLS transaction. API keys need an explicit REST scope.
func (s *Server) restTx(ctx context.Context, p *principal, write bool, fn func(pgx.Tx) error) error {
	if p.key != nil {
		scope := "rest:read"
		if write {
			scope = "rest:write"
		}
		// `*` deliberately does not imply REST access.
		if !slices.Contains(p.key.Scopes, scope) {
			return errForbidden("API key lacks scope '" + scope + "'")
		}
		return db.WithKeyRLS(ctx, s.pool, db.KeyIdentity{KeyID: p.key.KeyID, WorkspaceID: p.key.WorkspaceID, AppSlug: s.cfg.AppID}, fn)
	}
	return db.WithRLS(ctx, s.pool, p.claims, fn)
}

func (s *Server) restResolve(r *http.Request, profileHeader, table string) (*catalog, *apiError) {
	schema, e := s.restSchema(r, profileHeader)
	if e != nil {
		return nil, e
	}
	if !isIdent(table) {
		return nil, errBadRequest("Invalid table name")
	}
	cols, err := s.rest.loadColumns(r.Context(), s.pool, schema, table)
	if err != nil {
		return nil, &apiError{http.StatusInternalServerError, "internal_error", "Internal server error"}
	}
	if len(cols) == 0 {
		return nil, &apiError{http.StatusNotFound, "not_found", fmt.Sprintf("Table '%s.%s' not found", schema, table)}
	}
	return &catalog{schema: schema, tables: map[string][]column{table: cols}}, nil
}

func (s *Server) loadEmbeds(ctx context.Context, cat *catalog, table, spec string) *apiError {
	items, e := parseSelect(spec, 0)
	if e != nil {
		return e
	}
	var pairs [][2]string
	embeddedTables(items, table, &pairs)
	loaded := map[string]bool{}
	internal := &apiError{http.StatusInternalServerError, "internal_error", "Internal server error"}
	for _, pr := range pairs {
		parent, rel := pr[0], pr[1]
		if !loaded[parent] {
			loaded[parent] = true
			fks, err := s.rest.loadForeignKeys(ctx, s.pool, cat.schema, parent)
			if err != nil {
				return internal
			}
			for _, fk := range fks {
				if !slices.ContainsFunc(cat.fks, func(x foreignKey) bool { return x.Name == fk.Name && x.Table == fk.Table }) {
					cat.fks = append(cat.fks, fk)
				}
			}
		}
		if _, ok := cat.tables[rel]; !ok {
			cols, err := s.rest.loadColumns(ctx, s.pool, cat.schema, rel)
			if err != nil {
				return internal
			}
			if len(cols) == 0 {
				return errBadRequest("Unknown embedded table '%s'", rel)
			}
			cat.tables[rel] = cols
		}
	}
	return nil
}

func bindArgs(binds []bind, includeJSON bool) ([]any, error) {
	out := make([]any, 0, len(binds))
	for _, b := range binds {
		if j, ok := b.(jsonBind); ok {
			if !includeJSON {
				continue
			}
			raw, err := json.Marshal(j.v)
			if err != nil {
				return nil, err
			}
			out = append(out, string(raw))
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

func (s *Server) restRun(w http.ResponseWriter, r *http.Request, p *principal, write bool, b *built, wantCount bool) (json.RawMessage, *int64, bool) {
	args, err := bindArgs(b.binds, true)
	if err != nil {
		writeAPIError(w, errBadRequest("Body could not be encoded"))
		return nil, nil, false
	}
	var data []byte
	var total *int64
	err = s.restTx(r.Context(), p, write, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), b.sql, args...).Scan(&data); err != nil {
			return err
		}
		if wantCount && b.countSQL != "" {
			cargs, _ := bindArgs(b.binds, false)
			var n int64
			if err := tx.QueryRow(r.Context(), b.countSQL, cargs...).Scan(&n); err != nil {
				return err
			}
			total = &n
		}
		return nil
	})
	if ae, ok := err.(*apiError); ok {
		writeAPIError(w, ae)
		return nil, nil, false
	}
	if err != nil {
		dbError(w, err)
		return nil, nil, false
	}
	return data, total, true
}

func prefers(r *http.Request, token string) bool {
	for _, v := range r.Header.Values("Prefer") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func writeRaw(w http.ResponseWriter, status int, data json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// restStart authenticates, resolves the table and parses the query. Authentication
// comes first so anonymous callers learn nothing about the schema.
func (s *Server) restStart(w http.ResponseWriter, r *http.Request, profile string) (*principal, *catalog, *restParams, bool) {
	p, e := s.restPrincipal(r)
	if e != nil {
		writeAPIError(w, e)
		return nil, nil, nil, false
	}
	cat, e := s.restResolve(r, profile, r.PathValue("table"))
	if e != nil {
		writeAPIError(w, e)
		return nil, nil, nil, false
	}
	params, e := parseRestQuery(r.URL.RawQuery)
	if e != nil {
		writeAPIError(w, e)
		return nil, nil, nil, false
	}
	return p, cat, params, true
}

func (s *Server) restSelect(w http.ResponseWriter, r *http.Request) {
	p, cat, params, ok := s.restStart(w, r, "Accept-Profile")
	if !ok {
		return
	}
	table := r.PathValue("table")
	if e := s.loadEmbeds(r.Context(), cat, table, params.selectSpec); e != nil {
		writeAPIError(w, e)
		return
	}
	b, e := buildSelect(cat, table, params, restMaxRows)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	data, total, ok := s.restRun(w, r, p, false, b, prefers(r, "count=exact"))
	if !ok {
		return
	}
	if total != nil {
		var rows []json.RawMessage
		_ = json.Unmarshal(data, &rows)
		var start int64
		if params.offset != nil {
			start = max(*params.offset, 0)
		}
		rng := "*"
		if len(rows) > 0 {
			rng = fmt.Sprintf("%d-%d", start, start+int64(len(rows))-1)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("%s/%d", rng, *total))
	}
	writeRaw(w, http.StatusOK, data)
}

func readJSONBody(w http.ResponseWriter, r *http.Request) (any, bool) {
	var body any
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.UseNumber() // keep numbers exact for bigint/numeric columns
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return nil, false
	}
	return body, true
}

func (s *Server) restInsert(w http.ResponseWriter, r *http.Request) {
	p, cat, params, ok := s.restStart(w, r, "Content-Profile")
	if !ok {
		return
	}
	body, ok := readJSONBody(w, r)
	if !ok {
		return
	}
	merge, ignore := prefers(r, "resolution=merge-duplicates"), prefers(r, "resolution=ignore-duplicates")
	if (merge || ignore) && params.onConflict == "" {
		writeAPIError(w, errBadRequest("Upserts require ?on_conflict=<column[,column]>"))
		return
	}
	onConflict := ""
	if merge || ignore {
		onConflict = params.onConflict
	}
	table := r.PathValue("table")
	b, e := buildInsert(cat.schema, table, cat.tables[table], body, onConflict, merge)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if data, _, ok := s.restRun(w, r, p, true, b, false); ok {
		writeRaw(w, http.StatusCreated, data)
	}
}

func (s *Server) restUpdate(w http.ResponseWriter, r *http.Request) {
	p, cat, params, ok := s.restStart(w, r, "Content-Profile")
	if !ok {
		return
	}
	body, ok := readJSONBody(w, r)
	if !ok {
		return
	}
	table := r.PathValue("table")
	b, e := buildUpdate(cat.schema, table, cat.tables[table], body, params)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if data, _, ok := s.restRun(w, r, p, true, b, false); ok {
		writeRaw(w, http.StatusOK, data)
	}
}

func (s *Server) restDelete(w http.ResponseWriter, r *http.Request) {
	p, cat, params, ok := s.restStart(w, r, "Content-Profile")
	if !ok {
		return
	}
	table := r.PathValue("table")
	b, e := buildDelete(cat.schema, table, cat.tables[table], params)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if data, _, ok := s.restRun(w, r, p, true, b, false); ok {
		writeRaw(w, http.StatusOK, data)
	}
}

func (s *Server) restRPC(w http.ResponseWriter, r *http.Request) {
	p, e := s.restPrincipal(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	schema, e := s.restSchema(r, "Content-Profile")
	if e != nil {
		writeAPIError(w, e)
		return
	}
	name := r.PathValue("function")
	if !isIdent(name) {
		writeAPIError(w, errBadRequest("Invalid function name"))
		return
	}
	args := map[string]any{}
	if r.ContentLength != 0 {
		body, ok := readJSONBody(w, r)
		if !ok {
			return
		}
		switch b := body.(type) {
		case nil:
		case map[string]any:
			args = b
		default:
			writeAPIError(w, errBadRequest("RPC body must be a JSON object of named arguments"))
			return
		}
	}
	fns, err := s.rest.loadFunctions(r.Context(), s.pool, schema, name)
	if err != nil {
		dbError(w, err)
		return
	}
	if len(fns) == 0 {
		writeError(w, http.StatusNotFound, "not_found", fmt.Sprintf("Function '%s.%s' not found", schema, name))
		return
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	f, e := pickFunction(fns, keys)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if data, _, ok := s.restRun(w, r, p, !f.ReadOnly, buildRPC(schema, name, f, args), false); ok {
		writeRaw(w, http.StatusOK, data)
	}
}
