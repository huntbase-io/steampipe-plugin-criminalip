package criminalip

// Shared helpers for the search tables (banner, asset, exploit, banner stats)
// and the domain tables.

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// Records per call observed live. Paginate always advances by the number of
// records actually returned; these only matter for endpoints whose count is
// not a total (asset search), where a short page means the last page.
const (
	bannerSearchPageSize  = 10
	assetSearchPageSize   = 100
	exploitSearchPageSize = 10
	domainReportsPageSize = 100
)

// searchQueryQual returns the trimmed "query" equals qual.
func searchQueryQual(d *plugin.QueryData) string {
	return strings.TrimSpace(d.EqualsQualString("query"))
}

// searchParams builds the query string for a search call at the given offset.
func searchParams(query string, offset int) url.Values {
	return url.Values{"query": {query}, "offset": {strconv.Itoa(offset)}}
}

// searchQueryColumnDescription is shared by every table with a "query" qual.
const searchQueryColumnDescription = "The Criminal IP search query, for example 'product: OpenSSH country: KR'. Filter values cannot contain spaces."

// groupsColumnDescription is shared by the tables that expose data.groups.
const groupsColumnDescription = "The server's parse of the query: one entry per OR-group, each with the recognised filters and the keywords. A filter name the API does not recognise is silently treated as keywords, so check this column when a query returns no rows."

//// TRANSFORMS

// flexStringToInt converts an apiclient.FlexString (or string) holding an
// integer into an int64. "", null and non-numeric values become null.
func flexStringToInt(_ context.Context, d *transform.TransformData) (interface{}, error) {
	var s string
	switch v := d.Value.(type) {
	case nil:
		return nil, nil
	case apiclient.FlexString:
		s = string(v)
	case *apiclient.FlexString:
		if v == nil {
			return nil, nil
		}
		s = string(*v)
	case string:
		s = v
	case int, int32, int64:
		return v, nil
	default:
		return nil, nil
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	// Tolerate "22.0"-style numbers.
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == float64(int64(f)) {
		return int64(f), nil
	}
	return nil, nil
}
