package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// Small single-endpoint IP tables: privacy threat, VPN, hosting and DNS server
// safety.

//// criminalip_ip_privacy_threat (/v2/feature/ip/privacy-threat)

type ipPrivacyThreat struct {
	IP         string                 `json:"ip"`
	Timestamp  string                 `json:"timestamp"`
	Webcam     apiclient.Section[any] `json:"webcam"`
	IoT        apiclient.Section[any] `json:"iot"`
	AdminPage  apiclient.Section[any] `json:"admin_page"`
	NAS        apiclient.Section[any] `json:"nas"`
	OtherPorts apiclient.Section[any] `json:"other_ports"`
}

func tableCriminalIPIPPrivacyThreat(_ context.Context) *plugin.Table {
	const item = "Entries are {socket_type, port, protocol, has_vulnerability, confirmed_time, software, operating_systems}."
	cols := []*plugin.Column{
		ipColumn(),
		{Name: "timestamp", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Timestamp").Transform(naiveTimeToTimestamp), Description: "When the API answered the request (UTC)."},
	}
	cols = append(cols, sectionColumns("webcam", "Webcam", "Exposed webcams. "+item)...)
	cols = append(cols, sectionColumns("iot", "IoT", "Exposed IoT devices. "+item)...)
	cols = append(cols, sectionColumns("admin_page", "AdminPage", "Exposed admin pages. "+item)...)
	cols = append(cols, sectionColumns("nas", "NAS", "Exposed NAS devices. "+item)...)
	cols = append(cols, sectionColumns("other_ports", "OtherPorts", "Other exposed ports. "+item)...)
	return &plugin.Table{
		Name:        "criminalip_ip_privacy_threat",
		Description: "Devices and services exposed on an IPv4 address that threaten privacy: webcams, IoT, admin pages, NAS and other ports.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipPrivacyThreat]("criminalip_ip_privacy_threat", "/v2/feature/ip/privacy-threat"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: cols,
	}
}

//// criminalip_ip_vpn (/v1/ip/vpn)

type ipVPN struct {
	IP             string `json:"ip"`
	VPNInfo        any    `json:"vpn_info"`
	IsVPN          bool   `json:"is_vpn"`
	IsTor          bool   `json:"is_tor"`
	IsProxy        bool   `json:"is_proxy"`
	IsAnonymousVPN bool   `json:"is_anonymous_vpn"`
}

func tableCriminalIPIPVPN(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_ip_vpn",
		Description: "Whether an IPv4 address is a VPN, anonymous VPN, Tor node or proxy.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipVPN]("criminalip_ip_vpn", "/v1/ip/vpn"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: []*plugin.Column{
			ipColumn(),
			{Name: "is_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsVPN"), Description: "True if the IP is a VPN endpoint."},
			{Name: "is_anonymous_vpn", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsAnonymousVPN"), Description: "True if the IP is an anonymous VPN endpoint."},
			{Name: "is_tor", Type: proto.ColumnType_BOOL, Description: "True if the IP is a Tor node."},
			{Name: "is_proxy", Type: proto.ColumnType_BOOL, Description: "True if the IP is a proxy."},
			{Name: "vpn_info", Type: proto.ColumnType_JSON, Transform: transform.FromField("VPNInfo"), Description: "VPN details, such as the VPN provider, when known."},
		},
	}
}

//// criminalip_ip_hosting (/v1/ip/hosting)

type ipHosting struct {
	IP          string `json:"ip"`
	IsHosting   bool   `json:"is_hosting"`
	HostingInfo struct {
		AsNameIncludeHostingOrCloud string `json:"as_name_include_hosting_or_cloud"`
		DomainExistMoreThan5        any    `json:"domain_exist_more_than_5"`
		CloudIPRangeMatching        struct {
			IPRange      string `json:"ip_range"`
			CloudService string `json:"cloud_service"`
		} `json:"cloud_ip_range_matching"`
	} `json:"hosting_info"`
}

func tableCriminalIPIPHosting(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_ip_hosting",
		Description: "Whether an IPv4 address belongs to a hosting or cloud provider, and why.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[ipHosting]("criminalip_ip_hosting", "/v1/ip/hosting"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: []*plugin.Column{
			ipColumn(),
			{Name: "is_hosting", Type: proto.ColumnType_BOOL, Description: "True if the IP belongs to a hosting or cloud provider."},
			{Name: "cloud_service", Type: proto.ColumnType_STRING, Transform: transform.FromField("HostingInfo.CloudIPRangeMatching.CloudService").Transform(emptyStringToNil), Description: "Cloud service whose published IP ranges contain the IP, for example Google."},
			{Name: "cloud_ip_range", Type: proto.ColumnType_CIDR, Transform: transform.FromField("HostingInfo.CloudIPRangeMatching.IPRange"), Description: "The matching cloud IP range."},
			{Name: "as_name_hosting_match", Type: proto.ColumnType_STRING, Transform: transform.FromField("HostingInfo.AsNameIncludeHostingOrCloud").Transform(emptyStringToNil), Description: "AS name, when it contains a hosting or cloud keyword."},
			{Name: "domains_more_than_5", Type: proto.ColumnType_JSON, Transform: transform.FromField("HostingInfo.DomainExistMoreThan5"), Description: "Domains hosted on the IP, when more than 5 exist (a hosting signal)."},
			{Name: "hosting_info", Type: proto.ColumnType_JSON, Transform: transform.FromField("HostingInfo"), Description: "The raw hosting_info object."},
		},
	}
}

//// criminalip_dns_server_safety (/v1/feature/ip/is_safe_dns_server)

type dnsServerSafety struct {
	IP              string `json:"ip"`
	IsSafeDNSServer bool   `json:"is_safe_dns_server"`
	Reason          struct {
		IsMaliciousIP       bool `json:"is_malicious_ip"`
		OpenedUnusualPort   bool `json:"opened_unusual_port"`
		HasDNSVulnerability bool `json:"has_dns_vulnerability"`
		IsUnpublicDNS       bool `json:"is_unpublic_dns"`
	} `json:"reason"`
}

func tableCriminalIPDNSServerSafety(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_dns_server_safety",
		Description: "Whether an IPv4 address is a safe DNS server to use, with the reasons behind the verdict.",
		List: &plugin.ListConfig{
			Hydrate:    listIPLookup[dnsServerSafety]("criminalip_dns_server_safety", "/v1/feature/ip/is_safe_dns_server"),
			KeyColumns: ipKeyColumns(),
		},
		Columns: []*plugin.Column{
			ipColumn(),
			{Name: "is_safe_dns_server", Type: proto.ColumnType_BOOL, Transform: transform.FromField("IsSafeDNSServer"), Description: "True if the IP is considered a safe DNS server."},
			{Name: "is_malicious_ip", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Reason.IsMaliciousIP"), Description: "Reason: the IP is malicious."},
			{Name: "opened_unusual_port", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Reason.OpenedUnusualPort"), Description: "Reason: the IP has unusual open ports for a DNS server."},
			{Name: "has_dns_vulnerability", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Reason.HasDNSVulnerability"), Description: "Reason: the DNS service has known vulnerabilities."},
			{Name: "is_unpublic_dns", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Reason.IsUnpublicDNS"), Description: "Reason: the IP is not a known public DNS resolver."},
		},
	}
}
