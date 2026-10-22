package criminalip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

const envAPIKey = "CRIMINALIP_API_KEY"

// connect returns a cached API client for the connection.
func connect(ctx context.Context, d *plugin.QueryData) (*apiclient.Client, error) {
	cacheKey := "criminalip-client"
	if cached, ok := d.ConnectionManager.Cache.Get(cacheKey); ok {
		return cached.(*apiclient.Client), nil
	}

	cfg := GetConfig(d.Connection)
	apiKey := os.Getenv(envAPIKey)
	if cfg.APIKey != nil && *cfg.APIKey != "" {
		apiKey = *cfg.APIKey
	}
	baseURL := ""
	if cfg.BaseURL != nil {
		baseURL = *cfg.BaseURL
	}

	client, err := apiclient.New(apiclient.Config{
		APIKey:    apiKey,
		BaseURL:   baseURL,
		UserAgent: "huntbase-steampipe-plugin-criminalip/" + pluginVersion,
	})
	if err != nil {
		return nil, err
	}
	d.ConnectionManager.Cache.Set(cacheKey, client)
	return client, nil
}

// maxSearchResults is the record cap applied to a search when the query has
// no usable SQL LIMIT. It protects against accidentally paging through
// thousands of records (each page costs API credits).
func maxSearchResults(d *plugin.QueryData) int {
	cfg := GetConfig(d.Connection)
	if cfg.MaxSearchResults != nil && *cfg.MaxSearchResults > 0 {
		return min(*cfg.MaxSearchResults, apiclient.MaxReachableRecords)
	}
	return defaultMaxSearchResults
}

// searchRecordBudget returns how many records a paginated search may fetch:
// min(SQL LIMIT, max_search_results).
func searchRecordBudget(d *plugin.QueryData) int {
	limit := maxSearchResults(d)
	if d.QueryContext != nil && d.QueryContext.Limit != nil && *d.QueryContext.Limit > 0 {
		// A LIMIT can lower the budget but never raise it above
		// max_search_results: LIMIT 5000 would otherwise mean ~500 paid calls.
		limit = int(min(*d.QueryContext.Limit, int64(limit)))
	}
	return limit
}

// streamSearch runs a paginated search with the plugin's guard rails: the
// record budget, the list rate limiter before every page, SDK retries per
// page, and an early stop once Steampipe needs no more rows. emit should call
// d.StreamListItem.
func streamSearch[T any](ctx context.Context, d *plugin.QueryData, pageSize int, fetch apiclient.PageFetcher[T], emit func(T)) error {
	budget := searchRecordBudget(d)
	pageCalls := 0
	retrying := func(ctx context.Context, offset int) (*apiclient.Page[T], error) {
		if pageCalls > 0 {
			d.WaitForListRateLimit(ctx)
		}
		pageCalls++
		res, err := plugin.RetryHydrate(ctx, d, nil, func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
			return fetch(ctx, offset)
		}, retryConfig())
		if err != nil {
			// already retried at page level; stop the list-level retry repeating pages
			return nil, &exhaustedError{err}
		}
		return res.(*apiclient.Page[T]), nil
	}
	calls, err := apiclient.Paginate(ctx, retrying, apiclient.PaginateOptions{MaxRecords: budget, PageSize: pageSize}, func(r T) bool {
		emit(r)
		return d.RowsRemaining(ctx) > 0
	})
	plugin.Logger(ctx).Debug("criminalip.streamSearch", "table", d.Table.Name, "budget", budget, "api_calls", calls)
	return err
}

// exhaustedError marks an error whose retries were already spent.
type exhaustedError struct{ err error }

func (e *exhaustedError) Error() string { return e.err.Error() }
func (e *exhaustedError) Unwrap() error { return e.err }

// retryConfig is the plugin-wide retry policy: HTTP 429, HTTP 5xx and network
// timeouts, with Fibonacci backoff and at most 3 attempts.
func retryConfig() *plugin.RetryConfig {
	return &plugin.RetryConfig{
		ShouldRetryErrorFunc: shouldRetryError,
		MaxAttempts:          3,
		BackoffAlgorithm:     "Fibonacci",
		RetryInterval:        500,
		CappedDuration:       5000,
	}
}

func shouldRetryError(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData, err error) bool {
	var exhausted *exhaustedError
	if errors.As(err, &exhausted) {
		return false
	}
	if apiclient.IsRetryable(err) {
		plugin.Logger(ctx).Debug("criminalip.shouldRetryError", "retrying", err.Error())
		return true
	}
	return false
}

// isNotFoundError is used as the ignore predicate for Get calls.
func isNotFoundError(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData, err error) bool {
	return apiclient.IsNotFound(err)
}

// ipv4Qual returns the IPv4 address from the "ip" equals qual. ok is false
// for a missing qual or a non-IPv4 address (the API only supports IPv4, so we
// skip the call rather than spend a request on a guaranteed error).
func ipv4Qual(ctx context.Context, d *plugin.QueryData, column string) (string, bool) {
	q := d.EqualsQuals[column]
	if q == nil {
		return "", false
	}
	raw := q.GetInetValue().GetAddr()
	if raw == "" {
		raw = q.GetStringValue()
	}
	ip, err := normalizeIPv4(raw)
	if err != nil {
		plugin.Logger(ctx).Warn("criminalip.ipv4Qual", "table", d.Table.Name, "skipping", raw, "reason", err.Error())
		return "", false
	}
	return ip, true
}

// normalizeIPv4 validates s as an IPv4 address and returns its canonical form.
func normalizeIPv4(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "/"); i >= 0 {
		// inet quals may carry a /32 mask
		if s[i+1:] != "32" {
			return "", fmt.Errorf("%q is a network, not a single address", s)
		}
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address", s)
	}
	v4 := ip.To4()
	if v4 == nil || strings.Contains(s, ":") {
		return "", apiclient.ErrIPv6NotSupported
	}
	return v4.String(), nil
}

//// TRANSFORMS

// naiveTimeToTimestamp converts a timezone-less API timestamp string that is
// in UTC to a time. Empty or unparsable values become null.
func naiveTimeToTimestamp(_ context.Context, d *transform.TransformData) (interface{}, error) {
	return naiveTimeIn(d.Value, time.UTC), nil
}

// kstTimeToTimestamp converts a timezone-less API timestamp string that is in
// Korea Standard Time (UTC+9) to a UTC time. Banner and asset search use KST.
func kstTimeToTimestamp(_ context.Context, d *transform.TransformData) (interface{}, error) {
	return naiveTimeIn(d.Value, apiclient.KST), nil
}

func naiveTimeIn(value any, loc *time.Location) any {
	var s string
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		s = v
	case *string:
		if v == nil {
			return nil
		}
		s = *v
	case apiclient.FlexString:
		s = string(v)
	case time.Time:
		return v
	default:
		s = fmt.Sprint(v)
	}
	t, ok := apiclient.ParseTimeIn(s, loc)
	if !ok {
		return nil
	}
	return t
}

// flexBoolValue converts an apiclient.FlexBool to *bool (null when invalid).
func flexBoolValue(_ context.Context, d *transform.TransformData) (interface{}, error) {
	switch v := d.Value.(type) {
	case apiclient.FlexBool:
		return v.Ptr(), nil
	case *apiclient.FlexBool:
		if v == nil {
			return nil, nil
		}
		return v.Ptr(), nil
	}
	return d.Value, nil
}

// emptyStringToNil turns "" into null.
func emptyStringToNil(_ context.Context, d *transform.TransformData) (interface{}, error) {
	switch v := d.Value.(type) {
	case string:
		if v == "" {
			return nil, nil
		}
	case *string:
		if v == nil || *v == "" {
			return nil, nil
		}
		return *v, nil
	case apiclient.FlexString:
		if v == "" {
			return nil, nil
		}
		return string(v), nil
	}
	return d.Value, nil
}

// lengthOf returns the length of a slice, array or map value (0 for nil).
func lengthOf(_ context.Context, d *transform.TransformData) (interface{}, error) {
	if d.Value == nil {
		return 0, nil
	}
	v := reflect.ValueOf(d.Value)
	switch v.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return v.Len(), nil
	}
	return nil, nil
}
