package criminalip

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableCriminalIPAssetSearch(_ context.Context) *plugin.Table {
	cols := []*plugin.Column{
		{Name: "query", Type: proto.ColumnType_STRING, Transform: transform.FromField("Query"), Description: searchQueryColumnDescription},
	}
	cols = append(cols, bannerRecordColumns()...)
	cols = append(cols,
		&plugin.Column{Name: "groups", Type: proto.ColumnType_JSON, Transform: transform.FromField("Groups"), Description: groupsColumnDescription},
	)
	return &plugin.Table{
		Name:        "criminalip_asset_search",
		Description: "Search Criminal IP assets (one row per IP and port) with the Criminal IP query language. Returns 100 records per API call, compared with 10 for criminalip_banner_search.",
		List: &plugin.ListConfig{
			Hydrate:    listAssetSearch,
			KeyColumns: plugin.SingleColumn("query"),
		},
		Columns: cols,
	}
}

func listAssetSearch(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	query := searchQueryQual(d)
	if query == "" {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_asset_search.listAssetSearch", "connection_error", err)
		return nil, err
	}

	// Asset search's data.count is the page size, not a total, so a page
	// shorter than assetSearchPageSize is taken to be the last one.
	err = streamSearch(ctx, d, assetSearchPageSize, bannerSearchFetcher(c, "/v2/asset/search", query, false), func(r bannerRecord) {
		d.StreamListItem(ctx, r)
	})
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_asset_search.listAssetSearch", "api_error", err)
		return nil, err
	}
	return nil, nil
}
