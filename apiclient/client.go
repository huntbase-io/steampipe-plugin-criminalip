// Package apiclient is a small, dependency-free HTTP client for the Criminal IP
// REST API (https://api.criminalip.io).
//
// It knows about the API's quirks so that callers do not have to:
//
//   - Authentication is the "x-api-key" header. The key is never logged and never
//     included in error messages.
//   - Almost every error comes back as HTTP 200 with a non-200 integer "status" in
//     the JSON body. The client checks the body status and returns an *APIError.
//   - Cloudflare sits in front of the API. A POST without a body must carry
//     "Content-Length: 0" or Cloudflare answers with a 403 HTML challenge. HTML or
//     other non-JSON responses are returned as *TransportError and never parsed.
//   - "No Data" lookups (status 200, empty data, message "No Data ...") are not
//     errors. Use IsNoData on the decoded Envelope message to detect them.
//
// Basic use:
//
//	c, err := apiclient.New(apiclient.Config{APIKey: key})
//	var out apiclient.IPSummary
//	err = c.Get(ctx, "/v1/asset/ip/summary", url.Values{"ip": {"8.8.8.8"}}, &out)
//
// Envelope endpoints (search, domain, user) wrap their payload as
// {status, message, data}; decode them into Envelope[T]:
//
//	var env apiclient.Envelope[apiclient.SearchData[apiclient.BannerRecord]]
//	err = c.Get(ctx, "/v2/banner/search", url.Values{"query": {q}, "offset": {"0"}}, &env)
//
// Paginated searches should use Paginate, which enforces the API's offset limit
// and a caller-supplied record cap so that a query never pages unbounded.
//
// Retries are deliberately not done here: the Steampipe plugin drives them
// through the SDK's RetryConfig, using IsRetryable as the predicate.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the production API endpoint.
	DefaultBaseURL = "https://api.criminalip.io"
	// DefaultUserAgent identifies the plugin to the API.
	DefaultUserAgent = "huntbase-steampipe-plugin-criminalip"
	// DefaultTimeout bounds a single HTTP request. Full IP reports for busy IPs
	// are multi-megabyte and can take several seconds.
	DefaultTimeout = 60 * time.Second
	// maxBodyBytes protects against unbounded responses.
	maxBodyBytes = 64 << 20
)

// Config holds client settings. Only APIKey is required.
type Config struct {
	APIKey     string
	BaseURL    string
	UserAgent  string
	HTTPClient *http.Client
}

// Client calls the Criminal IP API. It is safe for concurrent use.
type Client struct {
	apiKey    string
	baseURL   string
	userAgent string
	http      *http.Client
}

// New returns a configured client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, ErrMissingAPIKey
	}
	c := &Client{
		apiKey:    strings.TrimSpace(cfg.APIKey),
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		userAgent: cfg.UserAgent,
		http:      cfg.HTTPClient,
	}
	if c.baseURL == "" {
		c.baseURL = DefaultBaseURL
	}
	if c.userAgent == "" {
		c.userAgent = DefaultUserAgent
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: DefaultTimeout}
	}
	return c, nil
}

// Get performs a GET request and decodes a successful JSON body into out.
// path is relative to the base URL, for example "/v1/asset/ip/summary".
func (c *Client) Get(ctx context.Context, path string, params url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, params, nil, "", out)
}

// Post performs a POST request with an empty body (Content-Length: 0).
func (c *Client) Post(ctx context.Context, path string, params url.Values, out any) error {
	return c.do(ctx, http.MethodPost, path, params, nil, "", out)
}

// PostForm performs a POST with an application/x-www-form-urlencoded body.
func (c *Client) PostForm(ctx context.Context, path string, form url.Values, out any) error {
	return c.do(ctx, http.MethodPost, path, nil, []byte(form.Encode()), "application/x-www-form-urlencoded", out)
}

func (c *Client) do(ctx context.Context, method, path string, params url.Values, body []byte, contentType string, out any) error {
	u := c.baseURL + "/" + strings.TrimLeft(path, "/")
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	// Always use a non-nil reader so that net/http sends an explicit
	// Content-Length (0 for an empty POST). Without it Cloudflare returns a
	// managed-challenge HTML page.
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return &TransportError{Method: method, Path: path, Err: err}
	}
	// For POST, net/http writes "Content-Length: 0" when ContentLength is 0 and
	// the body is http.NoBody (covered by TestPostSendsContentLengthZero).
	req.ContentLength = int64(len(body))
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return &TransportError{Method: method, Path: path, Err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &TransportError{Method: method, Path: path, HTTPStatus: resp.StatusCode, Err: err}
	}
	return decodeResponse(method, path, resp, raw, out)
}

// decodeResponse applies the envelope rules to a raw HTTP response.
func decodeResponse(method, path string, resp *http.Response, raw []byte, out any) error {
	if resp.Header.Get("cf-mitigated") != "" {
		return &TransportError{Method: method, Path: path, HTTPStatus: resp.StatusCode,
			Err: fmt.Errorf("blocked by Cloudflare (cf-mitigated: %s)", resp.Header.Get("cf-mitigated"))}
	}
	if !looksLikeJSON(resp.Header.Get("Content-Type"), raw) {
		return &TransportError{Method: method, Path: path, HTTPStatus: resp.StatusCode,
			Err: fmt.Errorf("unexpected non-JSON response (content-type %q, %d bytes)", resp.Header.Get("Content-Type"), len(raw))}
	}

	var probe struct {
		Status  *json.RawMessage `json:"status"`
		Message string           `json:"message"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return &TransportError{Method: method, Path: path, HTTPStatus: resp.StatusCode,
			Err: fmt.Errorf("invalid JSON response: %w", err)}
	}
	status := 0
	if probe.Status != nil {
		var f float64
		if err := json.Unmarshal(*probe.Status, &f); err == nil {
			status = int(f)
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if status == 0 || status == 200 {
			status = resp.StatusCode
		}
		return &APIError{Method: method, Path: path, HTTPStatus: resp.StatusCode, Status: status, Message: probe.Message}
	}
	if status != 0 && status != http.StatusOK {
		return &APIError{Method: method, Path: path, HTTPStatus: resp.StatusCode, Status: status, Message: probe.Message}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &TransportError{Method: method, Path: path, HTTPStatus: resp.StatusCode,
			Err: fmt.Errorf("decoding response: %w", err)}
	}
	return nil
}

func looksLikeJSON(contentType string, raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	if contentType != "" {
		mt, _, err := mime.ParseMediaType(contentType)
		if err == nil && (mt == "text/html" || mt == "application/xhtml+xml") {
			return false
		}
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

// IsNoData reports whether a status-200 message means "nothing found", for
// example "No Data (domain: google.com)".
func IsNoData(message string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(message)), "no data")
}
