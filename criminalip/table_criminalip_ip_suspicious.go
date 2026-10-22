package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// /v3/feature/ip/suspicious-info
type ipSuspicious struct {
	IP                   string                 `json:"ip"`
	Timestamp            string                 `json:"timestamp"`
	Score                ipScore                `json:"score"`
	Issues               ipIssues               `json:"issues"`
	RepresentativeDomain string                 `json:"representative_domain"`
	AbuseRecordCount     int64                  `json:"abuse_record_count"`
	Whois                apiclient.Section[any] `json:"whois"`
	IDS                  apiclient.Section[any] `json:"ids"`
	CurrentOpenedPort    apiclient.Section[any] `json:"current_opened_port"`
}

func tableCriminalIPIPSuspicious(_ context.Context) *plugin.Table {
	cols := []*plugin.Column{
		ipColumn(),
		{Name: "timestamp", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(naiveTimeToTimestamp), Description: "When the API answered the request (UTC)."},
		{Name: "score_inbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Inbound"), Description: "Inbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
		{Name: "score_outbound", Type: proto.ColumnType_STRING, Transform: transform.FromField("Score.Outbound"), Description: "Outbound risk score: Safe, Low, Moderate, Dangerous or Critical."},
		{Name: "abuse_record_count", Type: proto.ColumnType_INT, Description: "Number of abuse records for the IP."},
		{Name: "representative_domain", Type: proto.ColumnType_STRING, Transform: transform.FromField("RepresentativeDomain").Transform(emptyStringToNil), Description: "Representative domain hosted on the IP."},
		{Name: "issues", Type: proto.ColumnType_JSON, Description: "Issue flags (is_vpn, is_tor, is_proxy, is_hosting, is_cloud, is_mobile, is_darkweb, is_scanner, is_snort, is_anonymous_vpn)."},
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
	cols = append(cols, sectionColumns("whois", "Whois", "WHOIS and geolocation records.")...)
	cols = append(cols, sectionColumns("ids", "IDS", "IDS (Snort) detections.")...)
	cols = append(cols, sectionColumns("current_opened_port", "CurrentOpenedPort", "Open ports: port, socket_type, protocol, tags, is_vulnerability, software, operating_systems, confirmed_time.")...)

	return &plugin.Table{
		Name:        "criminalip_ip_suspicious",
		Description: "Compact risk profile for an IPv4 address (/v3/feature/ip/suspicious-info): scores, issue flags, abuse count, WHOIS, IDS hits and open ports. A good per-row enrichment call.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipSuspicious]("criminalip_ip_suspicious", "/v3/feature/ip/suspicious-info"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: cols,
	}
}
