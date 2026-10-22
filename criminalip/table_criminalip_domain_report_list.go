package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// domainReportsData is the data payload of /v1/domain/reports.
type domainReportsData struct {
	Count   int                  `json:"count"`
	Reports []domainReportRecord `json:"reports"`
}

// domainReportRecord is one existing domain scan. scan_id is a string here
// but an int in /v1/domain/scan, so FlexString takes either.
type domainReportRecord struct {
	ScanID         apiclient.FlexString `json:"scan_id"`
	URL            apiclient.FlexString `json:"url"`
	Title          apiclient.FlexString `json:"title"`
	RegDtime       apiclient.FlexString `json:"reg_dtime"`
	Score          apiclient.FlexString `json:"score"`
	Issue          any                  `json:"issue"`
	Technologies   any                  `json:"technologies"`
	ConnectedIPCnt apiclient.FlexString `json:"connected_ip_cnt"`
	CountryCode    any                  `json:"country_code"`
	FileExposure   any                  `json:"file_exposure"`
	Jarm           apiclient.FlexString `json:"jarm"`

	// Set by the plugin, not the API.
	Query      string `json:"-"`
	TotalCount int    `json:"-"`
}

func tableCriminalIPDomainReportList(_ context.Context) *plugin.Table {
	str := func(field string) *transform.ColumnTransforms {
		return transform.FromField(field).Transform(emptyStringToNil)
	}
	return &plugin.Table{
		Name:        "criminalip_domain_report_list",
		Description: "List existing Criminal IP domain scan reports for a domain or URL. Read-only: it never starts a new scan.",
		List: &plugin.ListConfig{
			Hydrate:    listDomainReportList,
			KeyColumns: plugin.SingleColumn("query"),
		},
		Columns: []*plugin.Column{
			{Name: "query", Type: proto.ColumnType_STRING, Transform: transform.FromField("Query"), Description: "The domain or URL to find reports for, for example example.com. Filters such as 'country: US' are also accepted."},
			{Name: "scan_id", Type: proto.ColumnType_INT, Transform: transform.FromField("ScanID").Transform(flexStringToInt), Description: "The scan ID. Use it with criminalip_domain_report to get the full report."},
			{Name: "url", Type: proto.ColumnType_STRING, Transform: str("URL"), Description: "The URL that was scanned."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: str("Title"), Description: "The page title at scan time."},
			{Name: "reg_dtime", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("RegDtime").Transform(naiveTimeToTimestamp), Description: "When the scan ran (API time without a timezone, assumed UTC)."},
			{Name: "score", Type: proto.ColumnType_STRING, Transform: str("Score"), Description: "The domain risk score: Safe, Low, Moderate, Dangerous or Critical. The API's casing varies, so compare case-insensitively."},
			{Name: "connected_ip_cnt", Type: proto.ColumnType_INT, Transform: transform.FromField("ConnectedIPCnt").Transform(flexStringToInt), Description: "The number of IP addresses the page connected to."},
			{Name: "jarm", Type: proto.ColumnType_STRING, Transform: str("Jarm"), Description: "The JARM TLS fingerprint of the server."},
			{Name: "issue", Type: proto.ColumnType_JSON, Transform: transform.FromField("Issue"), Description: "The issues detected by the scan, for example [\"mail_server\", \"diff_domain_favicon\"]."},
			{Name: "technologies", Type: proto.ColumnType_JSON, Transform: transform.FromField("Technologies"), Description: "The detected technologies as [{tech_name, logo_url}]."},
			{Name: "country_code", Type: proto.ColumnType_JSON, Transform: transform.FromField("CountryCode"), Description: "The country codes of the connected IP addresses."},
			{Name: "file_exposure", Type: proto.ColumnType_JSON, Transform: transform.FromField("FileExposure"), Description: "The exposed files found by the scan."},
			{Name: "total_count", Type: proto.ColumnType_INT, Transform: transform.FromField("TotalCount"), Description: "The total number of reports that match the query (data.count)."},
		},
	}
}

func listDomainReportList(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	query := searchQueryQual(d)
	if query == "" {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_domain_report_list.listDomainReportList", "connection_error", err)
		return nil, err
	}

	fetch := func(ctx context.Context, offset int) (*apiclient.Page[domainReportRecord], error) {
		var env apiclient.Envelope[domainReportsData]
		if err := c.Get(ctx, "/v1/domain/reports", searchParams(query, offset), &env); err != nil {
			return nil, err
		}
		return domainReportsPage(query, &env.Data), nil
	}
	err = streamSearch(ctx, d, 0, fetch, func(r domainReportRecord) {
		d.StreamListItem(ctx, r)
	})
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_domain_report_list.listDomainReportList", "api_error", err)
		return nil, err
	}
	return nil, nil
}

func domainReportsPage(query string, data *domainReportsData) *apiclient.Page[domainReportRecord] {
	for i := range data.Reports {
		data.Reports[i].Query = query
		data.Reports[i].TotalCount = data.Count
	}
	return &apiclient.Page[domainReportRecord]{Records: data.Reports, Total: data.Count}
}
