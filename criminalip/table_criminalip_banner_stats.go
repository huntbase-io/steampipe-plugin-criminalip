package criminalip

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

// bannerStatsData is the data payload of /v1/banner/stats. result maps an
// aggregation name such as "country_agg" to its buckets.
type bannerStatsData struct {
	Groups []apiclient.QueryGroup         `json:"groups"`
	Count  int                            `json:"count"`
	Result map[string][]bannerStatsBucket `json:"result"`
}

type bannerStatsBucket struct {
	Key      apiclient.FlexString `json:"key"`
	DocCount int64                `json:"doc_count"`
}

// bannerStatsRow is one (aggregation, key) bucket.
type bannerStatsRow struct {
	Query      string
	AggType    string
	Key        string
	DocCount   int64
	TotalCount int
	Groups     []apiclient.QueryGroup
}

// knownStatsAggs fixes the row order for the aggregations seen live; any
// other *_agg the API adds is appended in name order.
var knownStatsAggs = []string{"country_agg", "as_name_agg", "port_agg", "service_name_agg", "product_agg", "favicons_agg"}

// Columns use the plugin's default FromGo transform (agg_type -> AggType).
func tableCriminalIPBannerStats(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_banner_stats",
		Description: "Aggregate counts (by country, AS name, port, service, product and favicon) of the banners that match a Criminal IP search query. One API call per query.",
		List: &plugin.ListConfig{
			Hydrate:    listBannerStats,
			KeyColumns: plugin.SingleColumn("query"),
		},
		Columns: []*plugin.Column{
			{Name: "query", Type: proto.ColumnType_STRING, Description: searchQueryColumnDescription},
			{Name: "agg_type", Type: proto.ColumnType_STRING, Description: "The aggregation: country, as_name, port, service_name, product or favicons."},
			{Name: "key", Type: proto.ColumnType_STRING, Description: "The bucket value, for example 'kr' or '22'. The API returns keys in lower case."},
			{Name: "doc_count", Type: proto.ColumnType_INT, Description: "The number of matching banners in this bucket."},
			{Name: "total_count", Type: proto.ColumnType_INT, Description: "The total number of banners that match the query (data.count)."},
			{Name: "groups", Type: proto.ColumnType_JSON, Description: groupsColumnDescription},
		},
	}
}

func listBannerStats(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	query := searchQueryQual(d)
	if query == "" {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_banner_stats.listBannerStats", "connection_error", err)
		return nil, err
	}

	var env apiclient.Envelope[bannerStatsData]
	if err := c.Get(ctx, "/v1/banner/stats", url.Values{"query": {query}}, &env); err != nil {
		plugin.Logger(ctx).Error("criminalip_banner_stats.listBannerStats", "api_error", err)
		return nil, err
	}
	for _, row := range bannerStatsRows(query, &env.Data) {
		d.StreamListItem(ctx, row)
		if d.RowsRemaining(ctx) == 0 {
			break
		}
	}
	return nil, nil
}

// bannerStatsRows flattens the aggregation map into rows.
func bannerStatsRows(query string, data *bannerStatsData) []bannerStatsRow {
	order := make([]string, 0, len(data.Result))
	seen := map[string]bool{}
	for _, name := range knownStatsAggs {
		if _, ok := data.Result[name]; ok {
			order = append(order, name)
			seen[name] = true
		}
	}
	var extra []string
	for name := range data.Result {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	order = append(order, extra...)

	var rows []bannerStatsRow
	for _, name := range order {
		for _, b := range data.Result[name] {
			rows = append(rows, bannerStatsRow{
				Query:      query,
				AggType:    strings.TrimSuffix(name, "_agg"),
				Key:        string(b.Key),
				DocCount:   b.DocCount,
				TotalCount: data.Count,
				Groups:     data.Groups,
			})
		}
	}
	return rows
}
