package criminalip

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/memoize"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// Shared response types for the IP endpoints. These return flat objects
// (no data wrapper) with a body "status" field.

type ipScore struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

type ipIssues struct {
	IsVPN          bool `json:"is_vpn"`
	IsCloud        bool `json:"is_cloud"`
	IsTor          bool `json:"is_tor"`
	IsProxy        bool `json:"is_proxy"`
	IsHosting      bool `json:"is_hosting"`
	IsMobile       bool `json:"is_mobile"`
	IsDarkweb      bool `json:"is_darkweb"`
	IsScanner      bool `json:"is_scanner"`
	IsSnort        bool `json:"is_snort"`
	IsAnonymousVPN bool `json:"is_anonymous_vpn"`
}

// /v1/asset/ip/summary
type ipSummary struct {
	IP          string   `json:"ip"`
	Score       ipScore  `json:"score"`
	Country     string   `json:"country"`
	CountryCode string   `json:"country_code"`
	Region      string   `json:"region"`
	City        string   `json:"city"`
	ISP         string   `json:"isp"`
	OrgName     string   `json:"org_name"`
	AsNo        *int64   `json:"as_no"`
	PostalCode  string   `json:"postal_code"`
	Latitude    *float64 `json:"latitude"`
	Longitude   *float64 `json:"longitude"`
}

// /v1/asset/ip/report/summary
type ipReportSummary struct {
	Issue     []string `json:"issue"`
	Tags      []string `json:"tags"`
	IPScoring struct {
		Inbound     string `json:"inbound"`
		Outbound    string `json:"outbound"`
		IsMalicious bool   `json:"is_malicious"`
	} `json:"ip_scoring"`
	CurrentOpenPorts any `json:"current_open_ports"`
	Summary          struct {
		Connection struct {
			RepresentativeDomain *string `json:"representative_domain"`
			SSLCertificate       *bool   `json:"ssl_certificate"`
			IPAddressOwner       *string `json:"ip_address_owner"`
			Hostname             *string `json:"hostname"`
			ConnectedDomains     *int64  `json:"connected_domains"`
			Country              *string `json:"country"`
		} `json:"connection"`
		Detection struct {
			ProxyIP               bool  `json:"proxy_ip"`
			VPNIP                 bool  `json:"vpn_ip"`
			TorIP                 bool  `json:"tor_ip"`
			HostingIP             bool  `json:"hosting_ip"`
			MobileIP              bool  `json:"mobile_ip"`
			CDNIP                 bool  `json:"cdn_ip"`
			ScannerIP             bool  `json:"scanner_ip"`
			SpecialIssue          int64 `json:"special_issue"`
			AnonymousVPNDetection bool  `json:"anonymous_vpn_detection"`
		} `json:"detection"`
		Security struct {
			AbuseRecord     int64 `json:"abuse_record"`
			OpenPorts       int64 `json:"open_ports"`
			Vulnerabilities int64 `json:"vulnerabilities"`
			ExploitDB       int64 `json:"exploit_db"`
			PolicyViolation int64 `json:"policy_violation"`
			RemoteAddress   bool  `json:"remote_address"`
			NetworkDevice   bool  `json:"network_device"`
			AdminPage       bool  `json:"admin_page"`
			InvalidSSL      bool  `json:"invalid_ssl"`
		} `json:"security"`
		DNSService struct {
			RealIP bool `json:"real_ip"`
		} `json:"dns_service"`
	} `json:"summary"`
}

// /v2/asset/ip/report
type ipReport struct {
	IP              string                       `json:"ip"`
	Timestamp       string                       `json:"timestamp"`
	Issues          ipIssues                     `json:"issues"`
	Score           ipScore                      `json:"score"`
	UserSearchCount int64                        `json:"user_search_count"`
	ProtectedIP     apiclient.Section[any]       `json:"protected_ip"`
	Domain          apiclient.Section[any]       `json:"domain"`
	Whois           apiclient.Section[any]       `json:"whois"`
	Hostname        apiclient.Section[any]       `json:"hostname"`
	IDS             apiclient.Section[any]       `json:"ids"`
	VPN             apiclient.Section[any]       `json:"vpn"`
	AnonymousVPN    apiclient.Section[any]       `json:"anonymous_vpn"`
	Webcam          apiclient.Section[any]       `json:"webcam"`
	Honeypot        apiclient.Section[any]       `json:"honeypot"`
	IPCategory      apiclient.Section[any]       `json:"ip_category"`
	Mobile          apiclient.Section[any]       `json:"mobile"`
	Port            apiclient.Section[ipPort]    `json:"port"`
	Vulnerability   apiclient.Section[ipVulnRaw] `json:"vulnerability"`
}

type ipPort struct {
	OpenPortNo       int64               `json:"open_port_no"`
	PortStatus       string              `json:"port_status"`
	Protocol         string              `json:"protocol"`
	Socket           string              `json:"socket"`
	Banner           string              `json:"banner"`
	Tags             []string            `json:"tags"`
	DNSNames         *string             `json:"dns_names"`
	SDNCommonName    *string             `json:"sdn_common_name"`
	JarmHash         *string             `json:"jarm_hash"`
	SSLInfoRaw       *string             `json:"ssl_info_raw"`
	Technologies     any                 `json:"technologies"`
	IsVulnerability  bool                `json:"is_vulnerability"`
	ConfirmedTime    string              `json:"confirmed_time"`
	Software         []apiclient.Product `json:"software"`
	OperatingSystems []apiclient.Product `json:"operating_systems"`
}

type ipVulnRaw struct {
	CveID          string             `json:"cve_id"`
	CveDescription string             `json:"cve_description"`
	Cvssv2Vector   string             `json:"cvssv2_vector"`
	Cvssv2Score    *float64           `json:"cvssv2_score"`
	Cvssv3Vector   string             `json:"cvssv3_vector"`
	Cvssv3Score    *float64           `json:"cvssv3_score"`
	ListCpe        []string           `json:"list_cpe"`
	ListCwe        any                `json:"list_cwe"`
	ListEdb        []any              `json:"list_edb"`
	AppName        string             `json:"app_name"`
	AppVersion     string             `json:"app_version"`
	Vendor         string             `json:"vendor"`
	Type           string             `json:"type"`
	IsVuln         apiclient.FlexBool `json:"is_vuln"`
	TargetHw       string             `json:"target_hw"`
	TargetSw       string             `json:"target_sw"`
	OpenPortNoList any                `json:"open_port_no_list"`
	HaveMorePorts  bool               `json:"have_more_ports"`
	OpenPortNo     any                `json:"open_port_no"`
	ListChild      any                `json:"list_child"`
}

//// SHARED IP KEY COLUMNS AND LOOKUPS

// ipKeyColumns is the required, IPv4-only "ip" qual used by every IP table.
// `ip in (...)` is supported: the SDK calls List once per value.
func ipKeyColumns() plugin.KeyColumnSlice {
	return plugin.KeyColumnSlice{{Name: "ip", Require: plugin.Required, Operators: []string{"="}}}
}

func ipColumn() *plugin.Column {
	return &plugin.Column{Name: "ip", Type: proto.ColumnType_INET, Transform: transform.FromField("IP"), Description: "The IPv4 address that was looked up."}
}

// getIP calls a flat IP endpoint and decodes it into out.
func getIP(ctx context.Context, d *plugin.QueryData, path, ip string, extra url.Values, out any) error {
	c, err := connect(ctx, d)
	if err != nil {
		return err
	}
	params := url.Values{"ip": {ip}}
	for k, v := range extra {
		params[k] = v
	}
	return c.Get(ctx, path, params, out)
}

// listIPLookup builds a List function for a table whose single row comes from
// one flat IP endpoint. newT must return a pointer to a struct with an IP field.
func listIPLookup[T any](table, path string) plugin.HydrateFunc {
	return func(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
		ip, ok := ipv4Qual(ctx, d, "ip")
		if !ok {
			return nil, nil
		}
		out := new(T)
		if err := getIP(ctx, d, path, ip, nil, out); err != nil {
			plugin.Logger(ctx).Error(table+".list", "ip", ip, "api_error", err)
			return nil, err
		}
		d.StreamListItem(ctx, out)
		return nil, nil
	}
}

//// SHARED, CACHED /v2/asset/ip/report

// The full report is shared by criminalip_ip_report, criminalip_ip_port and
// criminalip_ip_vulnerability. It is memoized per (connection, ip, full) so a
// query joining these tables for one IP makes a single API call.

const ipReportCacheTTL = 5 * time.Minute

// ipReportResult carries the report with the effective full flag.
type ipReportResult struct {
	Full   bool
	Report *ipReport
}

// fullQual returns the effective `full` value: true unless `full_report = false`.
func fullQual(d *plugin.QueryData) bool {
	if q := d.EqualsQuals["full_report"]; q != nil {
		return q.GetBoolValue()
	}
	return true
}

func ipReportKeyColumns() plugin.KeyColumnSlice {
	return append(ipKeyColumns(), &plugin.KeyColumn{Name: "full_report", Require: plugin.Optional, Operators: []string{"="}})
}

func fullColumn() *plugin.Column {
	return &plugin.Column{Name: "full_report", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Full"),
		Description: "Whether the complete report was requested (default true). Set full_report = false for a faster report with every section capped at 20 items."}
}

func ipReportCacheKey(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	ip, _ := ipv4Qual(ctx, d, "ip")
	return "criminalip_ip_report|" + ip + "|" + strconv.FormatBool(fullQual(d)), nil
}

func getIPReportUncached(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	ip, ok := ipv4Qual(ctx, d, "ip")
	if !ok {
		return nil, nil
	}
	full := fullQual(d)
	plugin.Logger(ctx).Debug("criminalip.getIPReport", "api_call", "/v2/asset/ip/report", "ip", ip, "full", full)
	var report ipReport
	if err := getIP(ctx, d, "/v2/asset/ip/report", ip, url.Values{"full": {strconv.FormatBool(full)}}, &report); err != nil {
		return nil, err
	}
	return &ipReportResult{Full: full, Report: &report}, nil
}

var getIPReport = plugin.HydrateFunc(getIPReportUncached).Memoize(
	memoize.WithCacheKeyFunction(ipReportCacheKey),
	memoize.WithTtl(ipReportCacheTTL),
)

// fetchIPReport returns the cached report for the ip/full quals, or nil if the
// ip qual is not a valid IPv4 address.
func fetchIPReport(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (*ipReportResult, error) {
	if _, ok := ipv4Qual(ctx, d, "ip"); !ok {
		return nil, nil
	}
	res, err := getIPReport(ctx, d, h)
	if err != nil || res == nil {
		return nil, err
	}
	r, _ := res.(*ipReportResult)
	return r, nil
}
