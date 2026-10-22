package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// /v3/feature/ip/malicious-info
type ipMalicious struct {
	IP              string `json:"ip"`
	Timestamp       string `json:"timestamp"`
	IsMalicious     bool   `json:"is_malicious"`
	IsVPN           bool   `json:"is_vpn"`
	IsHosting       bool   `json:"is_hosting"`
	IsAnonymousVPN  bool   `json:"is_anonymous_vpn"`
	CanRemoteAccess bool   `json:"can_remote_access"`
	IsActor         bool   `json:"is_actor"`
	StdInfo         struct {
		RepresentativeDomain *string `json:"representative_domain"`
		Hostname             *string `json:"hostname"`
		// The API sends this key with a trailing space ("hostname_dtime ").
		// Accept both spellings in case it is ever fixed.
		HostnameDtimeSpace string  `json:"hostname_dtime "`
		HostnameDtime      string  `json:"hostname_dtime"`
		AsName             *string `json:"as_name"`
		Country            *string `json:"country"`
	} `json:"std_info"`
	Actor             apiclient.Section[any] `json:"actor"`
	CurrentOpenedPort apiclient.Section[any] `json:"current_opened_port"`
	RemotePort        apiclient.Section[any] `json:"remote_port"`
	Vulnerability     apiclient.Section[any] `json:"vulnerability"`
	IDS               apiclient.Section[any] `json:"ids"`
	ScanningRecord    apiclient.Section[any] `json:"scanning_record"`
	IPCategory        apiclient.Section[any] `json:"ip_category"`
}

// HostnameSeen returns the hostname timestamp regardless of key spelling.
func (m *ipMalicious) HostnameSeen() string {
	if m.StdInfo.HostnameDtimeSpace != "" {
		return m.StdInfo.HostnameDtimeSpace
	}
	return m.StdInfo.HostnameDtime
}

func sectionColumns(name, field, desc string) []*plugin.Column {
	return []*plugin.Column{
		{Name: name, Type: proto.ColumnType_JSON, Transform: transform.FromField(field + ".Data"), Description: desc},
		{Name: name + "_count", Type: proto.ColumnType_INT, Transform: transform.FromField(field + ".Count"), Description: "Number of " + name + " entries reported by the API."},
	}
}

func tableCriminalIPIPMalicious(_ context.Context) *plugin.Table {
	cols := []*plugin.Column{
		ipColumn(),
		{Name: "timestamp", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(naiveTimeToTimestamp), Description: "When the API answered the request (UTC)."},
		{Name: "is_malicious", Type: proto.ColumnType_BOOL, Description: "True if the IP is considered malicious."},
		{Name: "is_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsVPN"), Description: "True if the IP is a VPN endpoint."},
		{Name: "is_anonymous_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsAnonymousVPN"), Description: "True if the IP is an anonymous VPN endpoint."},
		{Name: "is_hosting", Type: proto.ColumnType_BOOL, Description: "True if the IP belongs to a hosting provider."},
		{Name: "can_remote_access", Type: proto.ColumnType_BOOL, Description: "True if a remote-access service is exposed."},
		{Name: "is_actor", Type: proto.ColumnType_BOOL, Description: "True if the IP is linked to a known threat actor."},
		{Name: "representative_domain", Type: proto.ColumnType_STRING, Transform: transform.FromField("StdInfo.RepresentativeDomain").Transform(emptyStringToNil), Description: "Representative domain hosted on the IP."},
		{Name: "hostname", Type: proto.ColumnType_STRING, Transform: transform.FromField("StdInfo.Hostname").Transform(emptyStringToNil), Description: "Hostname (PTR) of the IP."},
		{Name: "hostname_time", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromMethod("HostnameSeen").Transform(naiveTimeToTimestamp), Description: "When the hostname was observed (assumed UTC)."},
		{Name: "as_name", Type: proto.ColumnType_STRING, Transform: transform.FromField("StdInfo.AsName").Transform(emptyStringToNil), Description: "Autonomous system name (lower case)."},
		{Name: "country", Type: proto.ColumnType_STRING, Transform: transform.FromField("StdInfo.Country").Transform(emptyStringToNil), Description: "Country name."},
	}
	cols = append(cols, sectionColumns("actor", "Actor", "Threat actors linked to the IP: name, url, actor_dtime.")...)
	cols = append(cols, sectionColumns("current_opened_port", "CurrentOpenedPort", "Open ports: socket_type, port, protocol, software, operating_systems, has_vulnerability, TLS fields, confirmed_time.")...)
	cols = append(cols, sectionColumns("remote_port", "RemotePort", "Exposed remote-access ports.")...)
	cols = append(cols, sectionColumns("vulnerability", "Vulnerability", "Vulnerabilities found on the IP.")...)
	cols = append(cols, sectionColumns("ids", "IDS", "IDS (Snort) detections: classification, message, source_system, url, confirmed_time.")...)
	cols = append(cols, sectionColumns("scanning_record", "ScanningRecord", "Scanning activity from the IP seen by honeypots: log_date, dst_port, protocol_type, user_agent, message.")...)
	cols = append(cols, sectionColumns("ip_category", "IPCategory", "Threat categories: type, detect_source, confirmed_time. Can hold thousands of entries for popular IPs (2,689 for 8.8.8.8); select it only when needed.")...)

	return &plugin.Table{
		Name:        "criminalip_ip_malicious",
		Description: "Malicious-activity details for an IPv4 address (/v3/feature/ip/malicious-info): actors, scanning records, IDS hits and exposed ports.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipMalicious]("criminalip_ip_malicious", "/v3/feature/ip/malicious-info"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: cols,
	}
}
