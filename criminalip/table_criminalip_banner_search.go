package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// bannerRecord is one IP:port banner from /v2/banner/search or
// /v2/asset/search (both return the same v2 record shape).
//
// Several fields change type between records: status_code is an int or "",
// ssl_expired is a bool or "", and service_name/title/jarm/ssl_* may be null.
// The Flex types absorb that.
type bannerRecord struct {
	IPAddress             apiclient.FlexString `json:"ip_address"`
	OpenPortNo            apiclient.FlexString `json:"open_port_no"`
	SocketType            apiclient.FlexString `json:"socket_type"`
	ServiceName           apiclient.FlexString `json:"service_name"`
	StatusCode            apiclient.FlexString `json:"status_code"`
	Title                 apiclient.FlexString `json:"title"`
	Banner                apiclient.FlexString `json:"banner"`
	Country               apiclient.FlexString `json:"country"`
	City                  apiclient.FlexString `json:"city"`
	Latitude              *float64             `json:"latitude"`
	Longitude             *float64             `json:"longitude"`
	ASName                apiclient.FlexString `json:"as_name"`
	OrgName               apiclient.FlexString `json:"org_name"`
	Hostname              apiclient.FlexString `json:"hostname"`
	CloudSource           apiclient.FlexString `json:"cloud_source"`
	HasCVE                apiclient.FlexBool   `json:"has_cve"`
	Tags                  any                  `json:"tags"`
	ScanDtime             apiclient.FlexString `json:"scan_dtime"`
	Jarm                  apiclient.FlexString `json:"jarm"`
	Favicons              any                  `json:"favicons"`
	TechStacks            any                  `json:"tech_stacks"`
	Snort                 any                  `json:"snort"`
	Scanner               any                  `json:"scanner"`
	SSLInfo               apiclient.FlexString `json:"ssl_info"`
	SSLExpired            apiclient.FlexBool   `json:"ssl_expired"`
	SSLIssuerOrganization apiclient.FlexString `json:"ssl_issuer_organization"`
	SSLSubjectCommonName  apiclient.FlexString `json:"ssl_subject_common_name"`
	SSLSubjectCountry     apiclient.FlexString `json:"ssl_subject_country"`
	SSLSubjectOrg         apiclient.FlexString `json:"ssl_subject_organization"`
	Software              []apiclient.Product  `json:"software"`
	OperatingSystems      []apiclient.Product  `json:"operating_systems"`

	// Set by the plugin, not the API.
	Query      string                 `json:"-"`
	Groups     []apiclient.QueryGroup `json:"-"`
	TotalCount *int                   `json:"-"`
}

func tableCriminalIPBannerSearch(_ context.Context) *plugin.Table {
	cols := []*plugin.Column{
		{Name: "query", Type: proto.ColumnType_STRING, Transform: transform.FromField("Query"), Description: searchQueryColumnDescription},
	}
	cols = append(cols, bannerRecordColumns()...)
	cols = append(cols,
		&plugin.Column{Name: "total_count", Type: proto.ColumnType_INT, Transform: transform.FromField("TotalCount"), Description: "Total number of records that match the query (data.count). At most 10,000 of them can be paged through."},
		&plugin.Column{Name: "groups", Type: proto.ColumnType_JSON, Transform: transform.FromField("Groups"), Description: groupsColumnDescription},
	)
	return &plugin.Table{
		Name:        "criminalip_banner_search",
		Description: "Search Criminal IP's internet-wide banner index (one row per IP and port) with the Criminal IP query language.",
		List: &plugin.ListConfig{
			Hydrate:    listBannerSearch,
			KeyColumns: plugin.SingleColumn("query"),
		},
		Columns: cols,
	}
}

// bannerRecordColumns are the record columns shared by the banner and asset
// search tables.
func bannerRecordColumns() []*plugin.Column {
	str := func(field string) *transform.ColumnTransforms {
		return transform.FromField(field).Transform(emptyStringToNil)
	}
	return []*plugin.Column{
		{Name: "ip_address", Type: proto.ColumnType_IPADDR, Transform: str("IPAddress"), Description: "The IPv4 address the banner was collected from."},
		{Name: "open_port_no", Type: proto.ColumnType_INT, Transform: transform.FromField("OpenPortNo").Transform(flexStringToInt), Description: "The open port number."},
		{Name: "socket_type", Type: proto.ColumnType_STRING, Transform: str("SocketType"), Description: "The transport protocol, for example TCP or UDP."},
		{Name: "service_name", Type: proto.ColumnType_STRING, Transform: str("ServiceName"), Description: "The detected service, for example SSH or HTTPS. Use the 'service:' filter (not 'service_name:') to search on it."},
		{Name: "status_code", Type: proto.ColumnType_INT, Transform: transform.FromField("StatusCode").Transform(flexStringToInt), Description: "The HTTP status code, for web services."},
		{Name: "title", Type: proto.ColumnType_STRING, Transform: str("Title"), Description: "The HTML page title, for web services."},
		{Name: "banner", Type: proto.ColumnType_STRING, Transform: str("Banner"), Description: "The raw service banner."},
		{Name: "country", Type: proto.ColumnType_STRING, Transform: str("Country"), Description: "The ISO 3166-1 alpha-2 country code (upper case)."},
		{Name: "city", Type: proto.ColumnType_STRING, Transform: str("City"), Description: "The city."},
		{Name: "latitude", Type: proto.ColumnType_DOUBLE, Transform: transform.FromField("Latitude"), Description: "The latitude of the IP address."},
		{Name: "longitude", Type: proto.ColumnType_DOUBLE, Transform: transform.FromField("Longitude"), Description: "The longitude of the IP address."},
		{Name: "as_name", Type: proto.ColumnType_STRING, Transform: str("ASName"), Description: "The autonomous system name."},
		{Name: "org_name", Type: proto.ColumnType_STRING, Transform: str("OrgName"), Description: "The organization that owns the IP address."},
		{Name: "hostname", Type: proto.ColumnType_STRING, Transform: str("Hostname"), Description: "The hostname (PTR record) of the IP address."},
		{Name: "cloud_source", Type: proto.ColumnType_STRING, Transform: str("CloudSource"), Description: "The cloud provider hosting the IP address, if any."},
		{Name: "has_cve", Type: proto.ColumnType_BOOL, Transform: transform.FromField("HasCVE").Transform(flexBoolValue), Description: "True if Criminal IP associates known CVEs with this service. CVE IDs are not included; use criminalip_ip_vulnerability to get them."},
		{Name: "scan_dtime", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanDtime").Transform(naiveTimeToTimestamp), Description: "When the banner was collected (API time without a timezone, assumed UTC)."},
		{Name: "jarm", Type: proto.ColumnType_STRING, Transform: str("Jarm"), Description: "The JARM TLS fingerprint."},
		{Name: "ssl_expired", Type: proto.ColumnType_BOOL, Transform: transform.FromField("SSLExpired").Transform(flexBoolValue), Description: "True if the TLS certificate has expired. Null for non-TLS services."},
		{Name: "ssl_issuer_organization", Type: proto.ColumnType_STRING, Transform: str("SSLIssuerOrganization"), Description: "The organization of the TLS certificate issuer."},
		{Name: "ssl_subject_common_name", Type: proto.ColumnType_STRING, Transform: str("SSLSubjectCommonName"), Description: "The common name (CN) of the TLS certificate subject."},
		{Name: "ssl_subject_country", Type: proto.ColumnType_STRING, Transform: str("SSLSubjectCountry"), Description: "The country of the TLS certificate subject."},
		{Name: "ssl_subject_organization", Type: proto.ColumnType_STRING, Transform: str("SSLSubjectOrg"), Description: "The organization of the TLS certificate subject."},
		{Name: "ssl_info", Type: proto.ColumnType_STRING, Transform: str("SSLInfo"), Description: "The TLS certificate as raw text."},
		{Name: "software", Type: proto.ColumnType_JSON, Transform: transform.FromField("Software"), Description: "Detected software as [{product, version}]. Values can be the literal string 'Unknown'."},
		{Name: "operating_systems", Type: proto.ColumnType_JSON, Transform: transform.FromField("OperatingSystems"), Description: "Detected operating systems as [{product, version}]."},
		{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromField("Tags"), Description: "Criminal IP tags for the service, for example [\"DevOps\"]."},
		{Name: "tech_stacks", Type: proto.ColumnType_JSON, Transform: transform.FromField("TechStacks"), Description: "Detected web technologies."},
		{Name: "favicons", Type: proto.ColumnType_JSON, Transform: transform.FromField("Favicons"), Description: "Favicon hashes found on the service."},
		{Name: "snort", Type: proto.ColumnType_JSON, Transform: transform.FromField("Snort"), Description: "Snort IDS detections for the IP address."},
		{Name: "scanner", Type: proto.ColumnType_JSON, Transform: transform.FromField("Scanner"), Description: "Scanner activity recorded for the IP address."},
	}
}

func listBannerSearch(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	query := searchQueryQual(d)
	if query == "" {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_banner_search.listBannerSearch", "connection_error", err)
		return nil, err
	}

	// Banner search reports the true total in data.count, so Paginate stops at
	// it; PageSize 0 avoids guessing the plan's page size.
	err = streamSearch(ctx, d, 0, bannerSearchFetcher(c, "/v2/banner/search", query, true), func(r bannerRecord) {
		d.StreamListItem(ctx, r)
	})
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_banner_search.listBannerSearch", "api_error", err)
		return nil, err
	}
	return nil, nil
}

// bannerSearchFetcher returns a page fetcher for /v2/banner/search or
// /v2/asset/search. countIsTotal is false for asset search, whose data.count
// is the page size.
func bannerSearchFetcher(c *apiclient.Client, path, query string, countIsTotal bool) apiclient.PageFetcher[bannerRecord] {
	return func(ctx context.Context, offset int) (*apiclient.Page[bannerRecord], error) {
		var env apiclient.Envelope[apiclient.SearchData[bannerRecord]]
		if err := c.Get(ctx, path, searchParams(query, offset), &env); err != nil {
			return nil, err
		}
		return bannerPage(query, &env.Data, countIsTotal), nil
	}
}

// bannerPage annotates the records of one search page with the query, the
// parsed groups and (when meaningful) the total count.
func bannerPage(query string, data *apiclient.SearchData[bannerRecord], countIsTotal bool) *apiclient.Page[bannerRecord] {
	page := &apiclient.Page[bannerRecord]{Records: data.Result, Total: -1}
	var total *int
	if countIsTotal {
		page.Total = data.Count
		n := data.Count
		total = &n
	}
	for i := range page.Records {
		page.Records[i].Query = query
		page.Records[i].Groups = data.Groups
		page.Records[i].TotalCount = total
	}
	return page
}
