package criminalip

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// ipReportRow flattens ipReportResult so columns can use simple field paths.
type ipReportRow struct {
	Full bool
	ipReport
}

func tableCriminalIPIPReport(_ context.Context) *plugin.Table {
	cols := []*plugin.Column{
		ipColumn(),
		fullColumn(),
		{Name: "timestamp", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(naiveTimeToTimestamp), Description: "When Criminal IP produced the report (UTC)."},
		{Name: "score_inbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Inbound"), Description: "Inbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
		{Name: "score_outbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Outbound"), Description: "Outbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
		{Name: "user_search_count", Type: proto.ColumnType_INT, Description: "How many times Criminal IP users searched this IP."},
		{Name: "issues", Type: proto.ColumnType_JSON, Transform: transform.FromField("Issues"), Description: "Issue flags (is_vpn, is_tor, is_proxy, is_hosting, is_cloud, is_mobile, is_darkweb, is_scanner, is_snort, is_anonymous_vpn)."},
		{Name: "is_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsVPN"), Description: "True if the IP is a VPN endpoint."},
		{Name: "is_anonymous_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsAnonymousVPN"), Description: "True if the IP is an anonymous VPN endpoint."},
		{Name: "is_tor", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsTor"), Description: "True if the IP is a Tor node."},
		{Name: "is_proxy", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsProxy"), Description: "True if the IP is a proxy."},
		{Name: "is_cloud", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsCloud"), Description: "True if the IP belongs to a cloud provider."},
		{Name: "is_hosting", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsHosting"), Description: "True if the IP belongs to a hosting provider."},
		{Name: "is_mobile", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsMobile"), Description: "True if the IP belongs to a mobile network."},
		{Name: "is_darkweb", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsDarkweb"), Description: "True if the IP is associated with the dark web."},
		{Name: "is_scanner", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsScanner"), Description: "True if the IP is a known scanner."},
		{Name: "is_snort", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Issues.IsSnort"), Description: "True if the IP triggered Snort IDS rules."},
	}
	cols = append(cols, sectionColumns("whois", "Whois", "WHOIS and geolocation records: as_name, as_no, org_name, city, region, org_country_code, latitude, longitude, confirmed_time.")...)
	cols = append(cols, sectionColumns("hostname", "Hostname", "Hostnames seen for the IP: domain_name_rep, domain_name_full, confirmed_time.")...)
	cols = append(cols, sectionColumns("domain", "Domain", "Domains that resolve to the IP: domain, ip_type, registrar, create_date, email, confirmed_time. Can hold thousands of entries for popular IPs.")...)
	cols = append(cols, sectionColumns("protected_ip", "ProtectedIP", "Real IPs detected behind this IP: ip_address, confirmed_time.")...)
	cols = append(cols, sectionColumns("ids", "IDS", "IDS (Snort) detections: classification, message, source_system, url, confirmed_time.")...)
	cols = append(cols, sectionColumns("honeypot", "Honeypot", "Honeypot hits from the IP: dst_port, protocol_type, user_agent, message, log_date.")...)
	cols = append(cols, sectionColumns("ip_category", "IPCategory", "Threat categories: type (for example 'tor (Tor)', 'MISP', 'attack (Low)'), detect_source, confirmed_time.")...)
	cols = append(cols, sectionColumns("vpn", "VPN", "VPN records.")...)
	cols = append(cols, sectionColumns("anonymous_vpn", "AnonymousVPN", "Anonymous VPN records.")...)
	cols = append(cols, sectionColumns("webcam", "Webcam", "Exposed webcam records.")...)
	cols = append(cols, sectionColumns("mobile", "Mobile", "Mobile network records.")...)
	cols = append(cols, sectionColumns("ports", "Port", "Open ports with banners, software and certificates. See criminalip_ip_port for one row per port.")...)
	cols = append(cols, sectionColumns("vulnerabilities", "Vulnerability", "Vulnerabilities (CVEs). See criminalip_ip_vulnerability for one row per CVE.")...)

	return &plugin.Table{
		Name:        "criminalip_ip_report",
		Description: "The full Criminal IP report for an IPv4 address (/v2/asset/ip/report), with each section as JSON.",
		List: &plugin.ListConfig{
			Hydrate:    listIPReport,
			KeyColumns: ipReportKeyColumns(),
		},
		Columns: cols,
	}
}

func listIPReport(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	res, err := fetchIPReport(ctx, d, h)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_ip_report.listIPReport", "api_error", err)
		return nil, err
	}
	if res == nil || res.Report == nil {
		return nil, nil
	}
	d.StreamListItem(ctx, &ipReportRow{Full: res.Full, ipReport: *res.Report})
	return nil, nil
}
