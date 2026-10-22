package criminalip

// Tests for the search and domain tables (banner/asset/exploit search, banner
// stats, domain quick/report list/report/scan status). They decode the real
// API responses in testdata/fixtures and run every column's transform plus
// the SDK's value conversion, so a type change in the API shows up here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func readSearchFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func decodeSearchFixture[T any](t *testing.T, name string) apiclient.Envelope[T] {
	t.Helper()
	var env apiclient.Envelope[T]
	if err := json.Unmarshal(readSearchFixture(t, name), &env); err != nil {
		t.Fatalf("decoding fixture %s: %v", name, err)
	}
	return env
}

// rowValues runs the transform of every column of table (optionally only the
// columns fed by the given hydrate; nil means the list hydrate) against item,
// checks the SDK can convert the result to the column type, and returns the
// transformed values by column name.
func rowValues(t *testing.T, table *plugin.Table, hydrate plugin.HydrateFunc, item any) map[string]any {
	t.Helper()
	ctx := context.Background()
	out := map[string]any{}
	for _, col := range table.Columns {
		if (col.Hydrate == nil) != (hydrate == nil) {
			continue
		}
		if hydrate != nil && !sameFunc(col.Hydrate, hydrate) {
			continue
		}
		tr := col.Transform
		if tr == nil {
			tr = transform.FromGo()
		}
		v, err := tr.Execute(ctx, &transform.TransformData{HydrateItem: item, ColumnName: col.Name})
		if err != nil {
			t.Fatalf("%s.%s: transform error: %v", table.Name, col.Name, err)
		}
		if _, err := col.ToColumnValue(v); err != nil {
			t.Fatalf("%s.%s: value %#v does not convert to %s: %v", table.Name, col.Name, v, col.Type, err)
		}
		out[col.Name] = v
	}
	return out
}

func sameFunc(a, b plugin.HydrateFunc) bool {
	return funcName(a) == funcName(b)
}

func funcName(f plugin.HydrateFunc) string {
	return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
}

func deref(v any) any {
	switch p := v.(type) {
	case *int:
		if p == nil {
			return nil
		}
		return *p
	case *int64:
		if p == nil {
			return nil
		}
		return *p
	case *bool:
		if p == nil {
			return nil
		}
		return *p
	case *float64:
		if p == nil {
			return nil
		}
		return *p
	}
	return v
}

func wantValue(t *testing.T, vals map[string]any, col string, want any) {
	t.Helper()
	got := deref(vals[col])
	if gt, ok := got.(time.Time); ok {
		if wt, ok := want.(time.Time); ok && gt.Equal(wt) {
			return
		}
	}
	if got != want {
		t.Errorf("column %s = %#v (%T), want %#v (%T)", col, got, got, want, want)
	}
}

//// BANNER / ASSET SEARCH

func TestBannerSearchFixtures(t *testing.T) {
	table := tableCriminalIPBannerSearch(context.Background())
	for _, name := range []string{
		"v2_banner_search_openssh_kr.json",
		"v2_banner_search_service_ssh_kr.json",
		"v2_banner_search_or_not_keyword.json",
		"v2_banner_search_ip_cidr_8.8.8.0-24.json",
	} {
		t.Run(name, func(t *testing.T) {
			env := decodeSearchFixture[apiclient.SearchData[bannerRecord]](t, name)
			page := bannerPage("q", &env.Data, true)
			if len(page.Records) == 0 {
				t.Fatal("no records")
			}
			if page.Total != env.Data.Count {
				t.Errorf("page.Total = %d, want %d", page.Total, env.Data.Count)
			}
			for _, r := range page.Records {
				vals := rowValues(t, table, nil, r)
				if vals["ip_address"] == nil || vals["open_port_no"] == nil || vals["scan_dtime"] == nil {
					t.Errorf("missing core values: %v", vals)
				}
				wantValue(t, vals, "total_count", env.Data.Count)
				wantValue(t, vals, "query", "q")
				if g, ok := vals["groups"].([]apiclient.QueryGroup); !ok || len(g) == 0 {
					t.Errorf("groups = %#v", vals["groups"])
				}
			}
		})
	}
}

func TestBannerSearchValues(t *testing.T) {
	table := tableCriminalIPBannerSearch(context.Background())

	env := decodeSearchFixture[apiclient.SearchData[bannerRecord]](t, "v2_banner_search_openssh_kr.json")
	vals := rowValues(t, table, nil, bannerPage("product: OpenSSH country: KR", &env.Data, true).Records[0])
	wantValue(t, vals, "ip_address", "34.22.88.173")
	wantValue(t, vals, "open_port_no", int64(22))
	wantValue(t, vals, "service_name", "SSH")
	wantValue(t, vals, "country", "KR")
	wantValue(t, vals, "status_code", nil) // "" in the API
	wantValue(t, vals, "ssl_expired", nil) // "" in the API
	wantValue(t, vals, "title", nil)       // null in the API
	wantValue(t, vals, "org_name", nil)    // "" in the API
	wantValue(t, vals, "has_cve", false)
	wantValue(t, vals, "latitude", 37.5658)
	// "2026-10-22 07:20:04" in KST. The same scan batch appears in the IP
	// report (UTC) of the neighbouring 34.22.91.145 as confirmed_time
	// "2026-10-21 22:20:04".
	wantValue(t, vals, "scan_dtime", time.Date(2026, 10, 21, 22, 20, 4, 0, time.UTC))
	if sw, ok := vals["software"].([]apiclient.Product); !ok || len(sw) != 1 || sw[0].Product != "OpenSSH" {
		t.Errorf("software = %#v", vals["software"])
	}

	// status_code and ssl_expired switch to int and bool on web services.
	env = decodeSearchFixture[apiclient.SearchData[bannerRecord]](t, "v2_banner_search_or_not_keyword.json")
	recs := bannerPage("q", &env.Data, true).Records
	vals = rowValues(t, table, nil, recs[1])
	wantValue(t, vals, "status_code", int64(200))
	wantValue(t, vals, "ssl_expired", true)
	wantValue(t, vals, "service_name", nil) // null in the API
	if len(env.Data.Groups) != 2 {
		t.Errorf("OR query should parse into 2 groups, got %d", len(env.Data.Groups))
	}
}

func TestAssetSearchFixture(t *testing.T) {
	table := tableCriminalIPAssetSearch(context.Background())
	env := decodeSearchFixture[apiclient.SearchData[bannerRecord]](t, "v2_asset_search_openssh_kr.json")
	page := bannerPage("q", &env.Data, false)
	if page.Total != -1 {
		t.Errorf("asset search page.Total = %d, want -1 (data.count is the page size)", page.Total)
	}
	for _, c := range table.Columns {
		if c.Name == "total_count" {
			t.Error("criminalip_asset_search must not expose total_count: data.count is the page size")
		}
	}
	for _, r := range page.Records {
		vals := rowValues(t, table, nil, r)
		wantValue(t, vals, "open_port_no", int64(22))
	}
}

func TestUnknownFilterBecomesKeyword(t *testing.T) {
	env := decodeSearchFixture[apiclient.SearchData[bannerRecord]](t, "errors/unknown_filter_becomes_keyword.json")
	page := bannerPage("bogusfilter: abc", &env.Data, true)
	if len(page.Records) != 0 || page.Total != 0 {
		t.Fatalf("want an empty page, got %d records, total %d", len(page.Records), page.Total)
	}
	if len(env.Data.Groups) != 1 || len(env.Data.Groups[0].Keywords) != 2 || len(env.Data.Groups[0].Filters) != 0 {
		t.Errorf("groups = %+v", env.Data.Groups)
	}
}

// fakeSearchAPI serves pages of n synthetic records with the given total and
// records the offsets requested.
type fakeSearchAPI struct {
	mu       sync.Mutex
	offsets  []int
	total    int
	pageSize int
	count    func(pageLen int) int // the data.count to report
}

func (f *fakeSearchAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil || r.URL.Query().Get("query") == "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":400,"message":"Missing Parameter","data":{}}`))
			return
		}
		f.mu.Lock()
		f.offsets = append(f.offsets, offset)
		f.mu.Unlock()
		n := min(f.pageSize, max(f.total-offset, 0))
		result := make([]map[string]any, n)
		for i := range result {
			result[i] = map[string]any{"ip_address": "192.0.2.1", "open_port_no": offset + i}
		}
		body, _ := json.Marshal(map[string]any{
			"status": 200, "message": "success",
			"data": map[string]any{"groups": []any{}, "count": f.count(n), "result": result},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

func newFakeClient(t *testing.T, h http.Handler) *apiclient.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := apiclient.New(apiclient.Config{APIKey: "test", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBannerSearchPagination(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		countIsTotal bool
		pageSize     int // server page size
		optsPageSize int // what the table passes to streamSearch
		total        int
		maxRecords   int
		wantOffsets  []int
		wantRecords  int
	}{
		{"banner stops at total", "/v2/banner/search", true, 10, 0, 25, 100, []int{0, 10, 20}, 25},
		{"banner stops at record budget", "/v2/banner/search", true, 10, 0, 5000, 30, []int{0, 10, 20}, 30},
		{"asset stops on short page", "/v2/asset/search", false, 100, assetSearchPageSize, 240, 1000, []int{0, 100, 200}, 240},
		{"asset stops at record budget", "/v2/asset/search", false, 100, assetSearchPageSize, 5000, 150, []int{0, 100}, 150},
		{"banner empty result", "/v2/banner/search", true, 10, 0, 0, 100, []int{0}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeSearchAPI{total: tc.total, pageSize: tc.pageSize}
			if tc.countIsTotal {
				api.count = func(int) int { return tc.total }
			} else {
				api.count = func(n int) int { return n }
			}
			c := newFakeClient(t, api.handler(t))
			got := 0
			_, err := apiclient.Paginate(context.Background(),
				bannerSearchFetcher(c, tc.path, "port: 443", tc.countIsTotal),
				apiclient.PaginateOptions{MaxRecords: tc.maxRecords, PageSize: tc.optsPageSize},
				func(r bannerRecord) bool {
					if r.Query != "port: 443" {
						t.Errorf("record query = %q", r.Query)
					}
					got++
					return true
				})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.wantRecords {
				t.Errorf("records = %d, want %d", got, tc.wantRecords)
			}
			if len(api.offsets) != len(tc.wantOffsets) {
				t.Fatalf("offsets = %v, want %v", api.offsets, tc.wantOffsets)
			}
			for i := range api.offsets {
				if api.offsets[i] != tc.wantOffsets[i] {
					t.Fatalf("offsets = %v, want %v", api.offsets, tc.wantOffsets)
				}
			}
		})
	}
}

func TestSearchAPIErrorIsReturned(t *testing.T) {
	// "Results are limited" and similar come back as HTTP 200 with a body status.
	c := newFakeClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":400,"message":"Offset must not be over than 9900","data":{}}`))
	}))
	_, err := bannerSearchFetcher(c, "/v2/banner/search", "port: 443", true)(context.Background(), 0)
	if err == nil || apiclient.StatusOf(err) != 400 {
		t.Fatalf("want a status 400 APIError, got %v", err)
	}
}

//// BANNER STATS

func TestBannerStatsRows(t *testing.T) {
	table := tableCriminalIPBannerStats(context.Background())
	env := decodeSearchFixture[bannerStatsData](t, "v1_banner_stats_openssh_kr.json")
	rows := bannerStatsRows("product: OpenSSH country: KR", &env.Data)

	want := 0
	for _, b := range env.Data.Result {
		want += len(b)
	}
	if len(rows) != want || want == 0 {
		t.Fatalf("rows = %d, want %d", len(rows), want)
	}
	vals := rowValues(t, table, nil, rows[0])
	wantValue(t, vals, "agg_type", "country")
	wantValue(t, vals, "key", "kr")
	wantValue(t, vals, "doc_count", int64(283716))
	wantValue(t, vals, "total_count", 283716)
	wantValue(t, vals, "query", "product: OpenSSH country: KR")

	seen := map[string]bool{}
	for _, r := range rows {
		rowValues(t, table, nil, r)
		seen[r.AggType] = true
	}
	for _, a := range []string{"country", "as_name", "port", "service_name", "product"} {
		if !seen[a] {
			t.Errorf("no rows for agg_type %s", a)
		}
	}
}

func TestBannerStatsUnknownAggregation(t *testing.T) {
	data := &bannerStatsData{Count: 3, Result: map[string][]bannerStatsBucket{
		"zeta_agg":    {{Key: "z", DocCount: 1}},
		"country_agg": {{Key: "us", DocCount: 3}},
		"alpha_agg":   {{Key: "a", DocCount: 2}},
	}}
	rows := bannerStatsRows("q", data)
	got := []string{rows[0].AggType, rows[1].AggType, rows[2].AggType}
	want := []string{"country", "alpha", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("agg order = %v, want %v", got, want)
		}
	}
}

//// EXPLOIT SEARCH

func TestExploitSearchFixture(t *testing.T) {
	table := tableCriminalIPExploitSearch(context.Background())
	env := decodeSearchFixture[apiclient.SearchData[exploitRecord]](t, "v1_exploit_search_nginx.json")
	page := exploitPage("nginx", &env.Data)
	if page.Total != 127 || len(page.Records) == 0 {
		t.Fatalf("page total %d, %d records", page.Total, len(page.Records))
	}
	vals := rowValues(t, table, nil, page.Records[0])
	wantValue(t, vals, "edb_id", int64(52056))
	wantValue(t, vals, "platform", "PHP")
	wantValue(t, vals, "verify_code", "unverified")
	wantValue(t, vals, "edb_reg_date", time.Date(2024, 6, 26, 0, 0, 0, 0, time.UTC))
	wantValue(t, vals, "modify_dtime", time.Date(2024, 6, 28, 6, 49, 46, 0, time.UTC))
	wantValue(t, vals, "total_count", 127)
	for _, r := range page.Records {
		rowValues(t, table, nil, r)
	}
}

//// DOMAIN TABLES

func TestDomainQuickFixtures(t *testing.T) {
	table := tableCriminalIPDomainQuick(context.Background())

	hashEnv := decodeSearchFixture[domainQuickData](t, "v1_domain_quick_hash_view_google.com.json")
	hash := quickLookupFromEnvelope(&hashEnv)
	vals := rowValues(t, table, nil, domainQuickRow{Domain: "google.com", Hash: *hash})
	wantValue(t, vals, "domain", "google.com")
	wantValue(t, vals, "found", true)
	wantValue(t, vals, "result", "safe")
	wantValue(t, vals, "type", "trusted-domain")
	wantValue(t, vals, "call_count", int64(96364))
	wantValue(t, vals, "reg_dtime", time.Date(2023, 5, 15, 6, 13, 54, 0, time.UTC))

	malEnv := decodeSearchFixture[domainQuickData](t, "v1_domain_quick_malicious_view_google.com.json")
	vals = rowValues(t, table, getDomainQuickMalicious, quickLookupFromEnvelope(&malEnv))
	wantValue(t, vals, "is_malicious_listed", false) // "No Data (domain: google.com)"
	wantValue(t, vals, "malicious_type", nil)
	wantValue(t, vals, "malicious_call_count", nil)
	wantValue(t, vals, "malicious_reg_dtime", nil)

	trEnv := decodeSearchFixture[domainQuickData](t, "v1_domain_quick_trusted_view_google.com.json")
	vals = rowValues(t, table, getDomainQuickTrusted, quickLookupFromEnvelope(&trEnv))
	wantValue(t, vals, "is_trusted_listed", true)
	wantValue(t, vals, "trusted_type", "trusted-domain")
	wantValue(t, vals, "trusted_call_count", int64(96363))
}

func TestDomainQuickUsesDocumentedPath(t *testing.T) {
	var gotPath, gotDomain string
	c := newFakeClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotDomain = r.URL.Path, r.URL.Query().Get("domain")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readSearchFixture(t, "v1_domain_quick_malicious_view_google.com.json"))
	}))
	res, err := quickLookup(context.Background(), c, "malicious", "google.com")
	if err != nil {
		t.Fatal(err)
	}
	// The PDF's /v1/quick/... path returns 404; the working path has /domain/.
	if gotPath != "/v1/domain/quick/malicious/view" || gotDomain != "google.com" {
		t.Errorf("requested %s?domain=%s", gotPath, gotDomain)
	}
	if res.Found {
		t.Error("a No Data response must not be reported as found")
	}
}

func TestDomainReportListFixture(t *testing.T) {
	table := tableCriminalIPDomainReportList(context.Background())
	env := decodeSearchFixture[domainReportsData](t, "v1_domain_reports_example.com.json")
	page := domainReportsPage("example.com", &env.Data)
	if page.Total != 5519 || len(page.Records) == 0 {
		t.Fatalf("page total %d, %d records", page.Total, len(page.Records))
	}
	vals := rowValues(t, table, nil, page.Records[0])
	wantValue(t, vals, "scan_id", int64(73935155)) // a string in the API
	wantValue(t, vals, "score", "Safe")
	wantValue(t, vals, "url", "https://example.com")
	wantValue(t, vals, "connected_ip_cnt", int64(1))
	wantValue(t, vals, "total_count", 5519)
	wantValue(t, vals, "reg_dtime", time.Date(2026, 10, 22, 16, 17, 8, 0, time.UTC))
	for _, r := range page.Records {
		rowValues(t, table, nil, r)
	}
}

func TestDomainReportFixture(t *testing.T) {
	table := tableCriminalIPDomainReport(context.Background())
	env := decodeSearchFixture[json.RawMessage](t, "v2_domain_report_example.com.json")
	r, err := parseDomainReport(73944665, env.Message, env.Data)
	if err != nil || r == nil {
		t.Fatalf("parseDomainReport: %v, %v", r, err)
	}
	vals := rowValues(t, table, nil, *r)
	wantValue(t, vals, "scan_id", int64(73944665))
	wantValue(t, vals, "main_domain", "example.com")
	wantValue(t, vals, "score", "safe") // lower case here, "Safe" in the report list
	wantValue(t, vals, "score_percentage", float64(20))
	wantValue(t, vals, "ssl", false)
	wantValue(t, vals, "domain_created", time.Date(1995, 8, 14, 0, 0, 0, 0, time.UTC))
	wantValue(t, vals, "report_time", time.Date(2026, 10, 22, 21, 31, 31, 0, time.UTC))
	if m, ok := vals["main_domain_info"].(map[string]any); !ok || m["real_ip"] == nil {
		t.Errorf("main_domain_info = %#v", vals["main_domain_info"])
	}
	for _, c := range []string{"summary", "dns_record", "mapped_ip", "certificates", "technologies", "file_exposure", "classification"} {
		if vals[c] == nil {
			t.Errorf("column %s is null", c)
		}
	}

	if r, err := parseDomainReport(1, "No Data (scan_id: 1)", json.RawMessage(`{}`)); r != nil || err != nil {
		t.Errorf("No Data should be no row, got %v, %v", r, err)
	}
}

func TestDomainScanStatus(t *testing.T) {
	table := tableCriminalIPDomainScanStatus(context.Background())
	for _, tc := range []struct {
		fixture string
		pct     int64
		status  string
	}{
		{"v1_domain_status_inprogress.json", 10, "in_progress"},
		{"v1_domain_status_complete.json", 100, "complete"},
	} {
		env := decodeSearchFixture[domainScanStatusData](t, tc.fixture)
		vals := rowValues(t, table, nil, newDomainScanStatusRow(42, env.Data))
		wantValue(t, vals, "scan_id", int64(42))
		wantValue(t, vals, "scan_percentage", tc.pct)
		wantValue(t, vals, "status", tc.status)
	}
	for pct, status := range map[string]string{"-1": "failed", "-2": "domain_not_found", "0": "in_progress"} {
		row := newDomainScanStatusRow(1, domainScanStatusData{ScanPercentage: apiclient.FlexString(pct)})
		if row.Status != status {
			t.Errorf("scan_percentage %s: status %q, want %q", pct, row.Status, status)
		}
	}
}

func TestDomainUnknownScanIDIsNotFound(t *testing.T) {
	// Unknown scan IDs come back as HTTP 200 with status 420; the domain
	// report and status tables turn that into "no row".
	c := newFakeClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readSearchFixture(t, "errors/domain_status_unknown_scan_id_420.json"))
	}))
	if _, err := getDomainReport(context.Background(), c, 1); !apiclient.IsNotFound(err) {
		t.Fatalf("want IsNotFound, got %v", err)
	}
}

func TestDomainTablesAreReadOnly(t *testing.T) {
	// Scans cost credits and run asynchronously: no domain table may POST.
	var methods []string
	var mu sync.Mutex
	c := newFakeClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200,"message":"api success","data":{}}`))
	}))
	ctx := context.Background()
	_, _ = quickLookup(ctx, c, "hash", "example.com")
	_, _ = getDomainReport(ctx, c, 1)
	for _, m := range methods {
		if m[:4] != "GET " {
			t.Errorf("domain table made a non-GET request: %s", m)
		}
	}
}
