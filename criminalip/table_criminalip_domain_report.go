package criminalip

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// domainReport is the data payload of /v2/domain/report/{scan_id}. Only
// main_domain_info is typed; the other sections are passed through as JSON.
type domainReport struct {
	MainDomainInfo struct {
		MainDomain      apiclient.FlexString `json:"main_domain"`
		InsertedURL     apiclient.FlexString `json:"inserted_url"`
		ChangedURL      apiclient.FlexString `json:"changed_url"`
		Title           apiclient.FlexString `json:"title"`
		DomainCreated   apiclient.FlexString `json:"domain_created"`
		DomainRegistrar apiclient.FlexString `json:"domain_registrar"`
		DNSIPASN        apiclient.FlexString `json:"dns_ip_asn"`
		Jarm            apiclient.FlexString `json:"jarm"`
		DomainScore     struct {
			Score           apiclient.FlexString `json:"score"`
			ScoreNum        *float64             `json:"score_num"`
			ScorePercentage *float64             `json:"score_percentage"`
		} `json:"domain_score"`
	} `json:"main_domain_info"`
	MainDomainInfoRaw        any                  `json:"-"`
	Summary                  any                  `json:"summary"`
	Classification           any                  `json:"classification"`
	DNSRecord                any                  `json:"dns_record"`
	MappedIP                 any                  `json:"mapped_ip"`
	ConnectedIP              any                  `json:"connected_ip"`
	ConnectedIPInfo          any                  `json:"connected_ip_info"`
	ConnectedDomainSubdomain any                  `json:"connected_domain_subdomain"`
	Subdomains               any                  `json:"subdomains"`
	Certificates             any                  `json:"certificates"`
	MainCertificate          any                  `json:"main_certificate"`
	SSL                      apiclient.FlexBool   `json:"ssl"`
	SSLDetail                any                  `json:"ssl_detail"`
	Technologies             any                  `json:"technologies"`
	NetworkLogs              any                  `json:"network_logs"`
	PageNetworkingInfo       any                  `json:"page_networking_info"`
	PageRedirections         any                  `json:"page_redirections"`
	Links                    any                  `json:"links"`
	Frames                   any                  `json:"frames"`
	HTMLPageLinkDomains      any                  `json:"html_page_link_domains"`
	JavascriptVariables      any                  `json:"javascript_variables"`
	Cookies                  any                  `json:"cookies"`
	SecurityHeaders          any                  `json:"security_headers"`
	Screenshots              any                  `json:"screenshots"`
	FileExposure             any                  `json:"file_exposure"`
	DetectedProgram          any                  `json:"detected_program"`
	ReportTime               apiclient.FlexString `json:"report_time"`

	// Set by the plugin, not the API.
	ScanID int64 `json:"-"`
}

func tableCriminalIPDomainReport(_ context.Context) *plugin.Table {
	str := func(field string) *transform.ColumnTransforms {
		return transform.FromField(field).Transform(emptyStringToNil)
	}
	js := func(name, field, desc string) *plugin.Column {
		return &plugin.Column{Name: name, Type: proto.ColumnType_JSON, Transform: transform.FromField(field), Description: desc}
	}
	return &plugin.Table{
		Name:        "criminalip_domain_report",
		Description: "The full report of an existing Criminal IP domain scan, by scan ID. Read-only: it never starts a new scan. Find scan IDs with criminalip_domain_report_list.",
		List: &plugin.ListConfig{
			Hydrate:    listDomainReport,
			KeyColumns: plugin.SingleColumn("scan_id"),
		},
		Columns: []*plugin.Column{
			{Name: "scan_id", Type: proto.ColumnType_INT, Transform: transform.FromField("ScanID"), Description: "The scan ID of the report."},
			{Name: "main_domain", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.MainDomain"), Description: "The registered domain that was scanned."},
			{Name: "inserted_url", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.InsertedURL"), Description: "The URL submitted for scanning."},
			{Name: "changed_url", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.ChangedURL"), Description: "The final URL after redirects."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.Title"), Description: "The page title."},
			{Name: "domain_created", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("MainDomainInfo.DomainCreated").Transform(naiveTimeToTimestamp), Description: "The domain registration date from WHOIS."},
			{Name: "domain_registrar", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.DomainRegistrar"), Description: "The domain registrar."},
			{Name: "dns_ip_asn", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.DNSIPASN"), Description: "The AS name of the IP address the domain resolves to."},
			{Name: "jarm", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.Jarm"), Description: "The JARM TLS fingerprint of the server."},
			{Name: "score", Type: proto.ColumnType_STRING, Transform: str("MainDomainInfo.DomainScore.Score"), Description: "The domain risk score: safe, low, moderate, dangerous or critical. The API's casing varies, so compare case-insensitively."},
			{Name: "score_num", Type: proto.ColumnType_DOUBLE, Transform: transform.FromField("MainDomainInfo.DomainScore.ScoreNum"), Description: "The numeric domain score."},
			{Name: "score_percentage", Type: proto.ColumnType_DOUBLE, Transform: transform.FromField("MainDomainInfo.DomainScore.ScorePercentage"), Description: "The domain score as a percentage."},
			{Name: "ssl", Type: proto.ColumnType_BOOL, Transform: transform.FromField("SSL").Transform(flexBoolValue), Description: "True if the site was served over valid TLS."},
			{Name: "report_time", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("ReportTime").Transform(naiveTimeToTimestamp), Description: "When the report was generated. The API sends UTC without a timezone (verified live)."},
			js("main_domain_info", "MainDomainInfoRaw", "The main_domain_info section, including real_ip and favicon."),
			js("summary", "Summary", "About 40 phishing and abuse heuristics, for example url_phishing_prob, dga_score, fake_domain, punycode and abuse_record."),
			js("classification", "Classification", "The domain classification: dga_score, domain_type and google_safe_browsing."),
			js("dns_record", "DNSRecord", "DNS records (A, AAAA, CNAME, MX, NS, PTR, SOA) with a score for each IP address."),
			js("mapped_ip", "MappedIP", "The IP addresses the domain maps to, as [{ip, score, as_name, country}]."),
			js("connected_ip", "ConnectedIP", "The IP addresses the page connected to, as [{ip, score}]."),
			js("connected_ip_info", "ConnectedIPInfo", "Details of the connected IP addresses."),
			js("connected_domain_subdomain", "ConnectedDomainSubdomain", "The connected domains and their subdomains."),
			js("subdomains", "Subdomains", "The subdomains found."),
			js("certificates", "Certificates", "The TLS certificates seen, as [{subject, issuer, valid_from, valid_to, protocol, certificate_life}]."),
			js("main_certificate", "MainCertificate", "The site's main TLS certificate."),
			js("ssl_detail", "SSLDetail", "The TLS configuration details."),
			js("technologies", "Technologies", "The detected technologies, as [{name, version, categories, vulner}]."),
			js("network_logs", "NetworkLogs", "The network requests the page made."),
			js("page_networking_info", "PageNetworkingInfo", "A summary of the page's network activity."),
			js("page_redirections", "PageRedirections", "The redirects followed."),
			js("links", "Links", "The links on the page."),
			js("frames", "Frames", "The frames on the page."),
			js("html_page_link_domains", "HTMLPageLinkDomains", "The domains linked from the page and the IP addresses they map to."),
			js("javascript_variables", "JavascriptVariables", "The global JavaScript variables on the page."),
			js("cookies", "Cookies", "The cookies the page set."),
			js("security_headers", "SecurityHeaders", "The HTTP security headers."),
			js("screenshots", "Screenshots", "URLs of the page screenshots."),
			js("file_exposure", "FileExposure", "Exposed sensitive files, for example git_config, ds_store and phpinfo."),
			js("detected_program", "DetectedProgram", "Programs detected in the HTML source or through access."),
		},
	}
}

func listDomainReport(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	q := d.EqualsQuals["scan_id"]
	if q == nil {
		return nil, nil
	}
	scanID := q.GetInt64Value()
	if scanID <= 0 {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_domain_report.listDomainReport", "connection_error", err)
		return nil, err
	}
	report, err := getDomainReport(ctx, c, scanID)
	if err != nil {
		if apiclient.IsNotFound(err) {
			// status 420: no report exists for this scan_id.
			return nil, nil
		}
		plugin.Logger(ctx).Error("criminalip_domain_report.listDomainReport", "api_error", err)
		return nil, err
	}
	if report != nil {
		d.StreamListItem(ctx, *report)
	}
	return nil, nil
}

func getDomainReport(ctx context.Context, c *apiclient.Client, scanID int64) (*domainReport, error) {
	var env apiclient.Envelope[json.RawMessage]
	if err := c.Get(ctx, "/v2/domain/report/"+strconv.FormatInt(scanID, 10), nil, &env); err != nil {
		return nil, err
	}
	return parseDomainReport(scanID, env.Message, env.Data)
}

// parseDomainReport decodes the report data. main_domain_info is decoded
// twice: typed for the scalar columns and raw for the JSON column.
func parseDomainReport(scanID int64, message string, data json.RawMessage) (*domainReport, error) {
	if apiclient.IsNoData(message) || len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil, nil
	}
	var r domainReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("criminalip: decoding domain report %d: %w", scanID, err)
	}
	var raw struct {
		MainDomainInfo any `json:"main_domain_info"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("criminalip: decoding domain report %d: %w", scanID, err)
	}
	r.MainDomainInfoRaw = raw.MainDomainInfo
	r.ScanID = scanID
	return &r, nil
}
