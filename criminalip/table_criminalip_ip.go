package criminalip

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableCriminalIPIP(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_ip",
		Description: "Verdict, geolocation and ownership for an IPv4 address. Combines the IP summary and the report summary.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipSummary]("criminalip_ip", "/v1/asset/ip/summary"),
			KeyColumns: ipKeyColumns(),
		},
		HydrateConfig: []plugin.HydrateConfig{
			{Func: getIPReportSummary},
		},
		Columns: []*plugin.Column{
			ipColumn(),
			{Name: "score_inbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Inbound"), Description: "Inbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
			{Name: "score_outbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Outbound"), Description: "Outbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
			{Name: "is_malicious", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("IPScoring.IsMalicious"), Description: "True if Criminal IP considers the IP malicious."},
			{Name: "country", Type: proto.ColumnType_STRING, Description: "Country name."},
			{Name: "country_code", Type: proto.ColumnType_STRING, Transform: transform.FromField("CountryCode").Transform(transform.ToUpper), Description: "ISO 3166-1 alpha-2 country code (upper case)."},
			{Name: "region", Type: proto.ColumnType_STRING, Description: "Region or state."},
			{Name: "city", Type: proto.ColumnType_STRING, Description: "City."},
			{Name: "postal_code", Type: proto.ColumnType_STRING, Description: "Postal code."},
			{Name: "latitude", Type: proto.ColumnType_DOUBLE, Description: "Latitude."},
			{Name: "longitude", Type: proto.ColumnType_DOUBLE, Description: "Longitude."},
			{Name: "isp", Type: proto.ColumnType_STRING, Transform: transform.FromField("ISP"), Description: "Internet service provider."},
			{Name: "org_name", Type: proto.ColumnType_STRING, Description: "Organization that owns the IP."},
			{Name: "as_no", Type: proto.ColumnType_INT, Transform: transform.FromField("AsNo"), Description: "Autonomous system number."},

			// From /v1/asset/ip/report/summary
			{Name: "issues", Type: proto.ColumnType_JSON, Hydrate: getIPReportSummary, Transform: transform.FromField("Issue"), Description: "Issue labels, for example Tor, Snort, Hosting or Cloud Service."},
			{Name: "tags", Type: proto.ColumnType_JSON, Hydrate: getIPReportSummary, Transform: transform.FromField("Tags"), Description: "Tags assigned to the IP."},
			{Name: "hostname", Type: proto.ColumnType_STRING, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Connection.Hostname").Transform(emptyStringToNil), Description: "Hostname (PTR) of the IP."},
			{Name: "representative_domain", Type: proto.ColumnType_STRING, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Connection.RepresentativeDomain").Transform(emptyStringToNil), Description: "Representative domain hosted on the IP."},
			{Name: "ip_address_owner", Type: proto.ColumnType_STRING, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Connection.IPAddressOwner").Transform(emptyStringToNil), Description: "Owner of the IP address."},
			{Name: "connected_domains", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Connection.ConnectedDomains"), Description: "Number of domains connected to the IP."},
			{Name: "has_ssl_certificate", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Connection.SSLCertificate"), Description: "True if an SSL certificate was seen on the IP."},
			{Name: "is_proxy", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.ProxyIP"), Description: "True if the IP is a known proxy."},
			{Name: "is_vpn", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.VPNIP"), Description: "True if the IP is a known VPN endpoint."},
			{Name: "is_anonymous_vpn", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.AnonymousVPNDetection"), Description: "True if the IP is an anonymous VPN endpoint."},
			{Name: "is_tor", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.TorIP"), Description: "True if the IP is a Tor node."},
			{Name: "is_hosting", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.HostingIP"), Description: "True if the IP belongs to a hosting provider."},
			{Name: "is_mobile", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.MobileIP"), Description: "True if the IP belongs to a mobile network."},
			{Name: "is_cdn", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.CDNIP"), Description: "True if the IP belongs to a CDN."},
			{Name: "is_scanner", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.ScannerIP"), Description: "True if the IP is a known internet scanner."},
			{Name: "special_issue_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Detection.SpecialIssue"), Description: "Number of special issues detected."},
			{Name: "abuse_record_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.AbuseRecord"), Description: "Number of abuse records for the IP."},
			{Name: "open_port_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.OpenPorts"), Description: "Number of open ports currently seen."},
			{Name: "vulnerability_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.Vulnerabilities"), Description: "Number of vulnerabilities (CVEs) found."},
			{Name: "exploit_db_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.ExploitDB"), Description: "Number of Exploit-DB entries matching the IP's vulnerabilities."},
			{Name: "policy_violation_count", Type: proto.ColumnType_INT, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.PolicyViolation"), Description: "Number of policy violations."},
			{Name: "has_remote_address", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.RemoteAddress"), Description: "True if a remote-access service is exposed."},
			{Name: "has_network_device", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.NetworkDevice"), Description: "True if a network device interface is exposed."},
			{Name: "has_admin_page", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.AdminPage"), Description: "True if an admin page is exposed."},
			{Name: "has_invalid_ssl", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.Security.InvalidSSL"), Description: "True if an invalid SSL certificate was seen."},
			{Name: "is_real_ip", Type: proto.ColumnType_BOOL, Hydrate: getIPReportSummary, Transform: transform.FromField("Summary.DNSService.RealIP"), Description: "True if the IP was identified as the real IP behind a DNS or CDN service."},
			{Name: "open_ports", Type: proto.ColumnType_JSON, Hydrate: getIPReportSummary, Transform: transform.FromField("CurrentOpenPorts"), Description: "Currently open ports, as {TCP: [{port, has_vulnerability}], UDP: [...]}."},
		},
	}
}

func getIPReportSummary(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	summary, ok := h.Item.(*ipSummary)
	if !ok || summary.IP == "" {
		return nil, nil
	}
	ip, err := normalizeIPv4(summary.IP)
	if err != nil {
		return nil, nil
	}
	var out ipReportSummary
	if err := getIP(ctx, d, "/v1/asset/ip/report/summary", ip, nil, &out); err != nil {
		plugin.Logger(ctx).Error("criminalip_ip.getIPReportSummary", "ip", ip, "api_error", err)
		return nil, err
	}
	return &out, nil
}
