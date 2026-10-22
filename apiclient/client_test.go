package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "test-key-should-never-leak"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

// serve returns a client whose server answers every request with body.
func serve(t *testing.T, httpStatus int, contentType string, body []byte, check func(*http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(httpStatus)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{APIKey: testKey, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRequiresKey(t *testing.T) {
	if _, err := New(Config{APIKey: "  "}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}

func TestGetSendsAuthAndParams(t *testing.T) {
	c := serve(t, 200, "application/json", fixture(t, "v1_asset_ip_summary_8.8.8.8.json"), func(r *http.Request) {
		if r.Header.Get("x-api-key") != testKey {
			t.Errorf("missing x-api-key header")
		}
		if r.URL.Path != "/v1/asset/ip/summary" || r.URL.Query().Get("ip") != "8.8.8.8" {
			t.Errorf("unexpected request %s", r.URL)
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "huntbase") {
			t.Errorf("unexpected UA %q", r.Header.Get("User-Agent"))
		}
	})
	var out struct {
		IP    string `json:"ip"`
		AsNo  int    `json:"as_no"`
		Score struct {
			Inbound string `json:"inbound"`
		} `json:"score"`
	}
	if err := c.Get(context.Background(), "/v1/asset/ip/summary", url.Values{"ip": {"8.8.8.8"}}, &out); err != nil {
		t.Fatal(err)
	}
	if out.IP != "8.8.8.8" || out.AsNo == 0 || out.Score.Inbound == "" {
		t.Fatalf("bad decode: %+v", out)
	}
}

func TestPostSendsContentLengthZero(t *testing.T) {
	c := serve(t, 200, "application/json", fixture(t, "user_me.json"), func(r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("want POST, got %s", r.Method)
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			t.Errorf("want Content-Length: 0, got %d %v", r.ContentLength, r.TransferEncoding)
		}
		if _, ok := r.Header["Content-Length"]; !ok {
			t.Errorf("Content-Length header not sent; Cloudflare would challenge this request")
		}
	})
	var env Envelope[map[string]any]
	if err := c.Post(context.Background(), "/v1/user/me", nil, &env); err != nil {
		t.Fatal(err)
	}
	if env.Data["email"] == nil {
		t.Fatalf("bad decode: %+v", env)
	}
}

func TestPostFormBody(t *testing.T) {
	c := serve(t, 200, "application/json", []byte(`{"status":200,"message":"ok","data":{}}`), func(r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("query") != "example.com" {
			t.Errorf("form body not sent: %v", r.PostForm)
		}
	})
	if err := c.PostForm(context.Background(), "/x", url.Values{"query": {"example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBodyStatusErrors(t *testing.T) {
	cases := []struct {
		fixture    string
		httpStatus int
		status     int
		notFound   bool
		badRequest bool
		retryable  bool
	}{
		{"errors/missing_api_key.json", 200, 403, false, false, false},
		{"errors/concurrency_limit_403.json", 200, 403, false, false, true},
		{"errors/invalid_api_key.json", 200, 500, false, false, false},
		{"errors/invalid_ip.json", 200, 400, false, true, false},
		{"errors/ipv6_not_supported.json", 200, 400, false, true, false},
		{"errors/missing_ip_param.json", 200, 400, false, true, false},
		{"errors/wrong_path_404.json", 200, 404, true, false, false},
		{"errors/domain_status_unknown_scan_id_420.json", 200, 420, true, true, false},
		{"errors/domain_scan_still_scanning.json", 200, 400, false, true, false},
		{"errors/banner_search_missing_offset_http400.json", 400, 400, false, true, false},
		{"errors/domain_lite_reports_500.json", 503, 500, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			c := serve(t, tc.httpStatus, "application/json", fixture(t, tc.fixture), nil)
			var out map[string]any
			err := c.Get(context.Background(), "/p", nil, &out)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want *APIError, got %T %v", err, err)
			}
			if apiErr.Status != tc.status {
				t.Errorf("status = %d, want %d", apiErr.Status, tc.status)
			}
			if IsNotFound(err) != tc.notFound || IsBadRequest(err) != tc.badRequest || IsRetryable(err) != tc.retryable {
				t.Errorf("predicates wrong: notFound=%v badRequest=%v retryable=%v", IsNotFound(err), IsBadRequest(err), IsRetryable(err))
			}
			if strings.Contains(err.Error(), testKey) {
				t.Errorf("error leaks API key: %v", err)
			}
		})
	}
}

func TestCloudflareChallengeAndHTML(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><title>Just a moment...</title></html>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		switch r.URL.Path {
		case "/challenge":
			w.Header().Set("cf-mitigated", "challenge")
			w.WriteHeader(403)
		case "/html500":
			w.WriteHeader(500)
		}
		_, _ = w.Write(html)
	}))
	defer srv.Close()
	c, _ := New(Config{APIKey: testKey, BaseURL: srv.URL})

	for path, retryable := range map[string]bool{"/challenge": false, "/html500": true, "/html200": false} {
		err := c.Get(context.Background(), path, nil, &map[string]any{})
		var tErr *TransportError
		if !errors.As(err, &tErr) {
			t.Fatalf("%s: want *TransportError, got %T %v", path, err, err)
		}
		if IsRetryable(err) != retryable {
			t.Errorf("%s: retryable = %v, want %v", path, IsRetryable(err), retryable)
		}
	}
}

func TestRateLimitedIsRetryable(t *testing.T) {
	c := serve(t, 429, "application/json", []byte(`{"status":429,"message":"too many requests"}`), nil)
	err := c.Get(context.Background(), "/p", nil, nil)
	if !IsRetryable(err) {
		t.Fatalf("429 should be retryable: %v", err)
	}
}

func TestNoDataIsNotAnError(t *testing.T) {
	c := serve(t, 200, "application/json", fixture(t, "v1_domain_quick_malicious_view_google.com.json"), nil)
	var env Envelope[map[string]any]
	if err := c.Get(context.Background(), "/v1/domain/quick/malicious/view", url.Values{"domain": {"google.com"}}, &env); err != nil {
		t.Fatal(err)
	}
	if !IsNoData(env.Message) || len(env.Data) != 0 {
		t.Fatalf("expected empty no-data result, got %+v", env)
	}
}

// The API allows one call in flight per key, and Steampipe runs list calls
// for `ip in (...)` concurrently, so the client must serialise per key, across
// clients (connections) that share the key.
func TestRequestsAreSerialisedPerKey(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200}`))
	}))
	t.Cleanup(srv.Close)

	key := "serialise-" + t.Name()
	c1, _ := New(Config{APIKey: key, BaseURL: srv.URL})
	c2, _ := New(Config{APIKey: key, BaseURL: srv.URL})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		c := c1
		if i%2 == 1 {
			c = c2
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Get(context.Background(), "/x", nil, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("max requests in flight for one key = %d, want 1", got)
	}
}

func TestDifferentKeysAreNotSerialised(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200}`))
	}))
	t.Cleanup(srv.Close)
	a, _ := New(Config{APIKey: "key-a-" + t.Name(), BaseURL: srv.URL})
	b, _ := New(Config{APIKey: "key-b-" + t.Name(), BaseURL: srv.URL})
	var wg sync.WaitGroup
	for _, c := range []*Client{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Get(context.Background(), "/x", nil, nil) }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("requests with different keys were serialised")
		}
	}
	close(release)
	wg.Wait()
}

func TestWaitingForSlotHonoursContext(t *testing.T) {
	key := "ctx-" + t.Name()
	c, _ := New(Config{APIKey: key, BaseURL: "http://127.0.0.1:1"})
	c.slot <- struct{}{} // another request holds the slot
	defer func() { <-c.slot }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := c.Get(ctx, "/x", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

// net/http forwards custom headers such as x-api-key on redirects, so an
// off-host redirect must not be followed.
func TestOffHostRedirectIsNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" {
			leaked.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200}`))
	}))
	t.Cleanup(other.Close)
	// Use "localhost" for the redirect target so the host differs from 127.0.0.1.
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	c := serveHandler(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/elsewhere", http.StatusFound)
	})
	err := c.Get(context.Background(), "/v1/asset/ip/summary", nil, nil)
	if err == nil {
		t.Fatal("want an error for an off-host redirect")
	}
	if leaked.Load() {
		t.Fatal("x-api-key was sent to the redirect target")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatal("error leaks the key")
	}
}

func serveHandler(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{APIKey: testKey, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
