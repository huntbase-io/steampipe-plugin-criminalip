package criminalip

// Tests for the IP tables. Each decodes a real API response from
// testdata/fixtures into the table's row type and runs every column's
// transform and SDK value conversion (rowValues, in search_tables_test.go).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func decodeIPFixture[T any](t *testing.T, name string) *T {
	t.Helper()
	out := new(T)
	if err := json.Unmarshal(readSearchFixture(t, name), out); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return out
}

func TestPluginTablesValidate(t *testing.T) {
	p := Plugin(context.Background())
	for name, table := range p.TableMap {
		if table.Name != name {
			t.Errorf("table %q registered as %q", table.Name, name)
		}
		if table.List == nil && table.Get == nil {
			t.Errorf("%s has no List or Get", name)
		}
		seen := map[string]bool{}
		for _, c := range table.Columns {
			if seen[c.Name] {
				t.Errorf("%s: duplicate column %s", name, c.Name)
			}
			seen[c.Name] = true
			if c.Description == "" {
				t.Errorf("%s.%s has no description", name, c.Name)
			}
			if c.Name == "api_key" {
				t.Errorf("%s exposes api_key", name)
			}
		}
	}
}

func TestIPTablesRequireIPQual(t *testing.T) {
	p := Plugin(context.Background())
	for _, name := range []string{"criminalip_ip", "criminalip_ip_report", "criminalip_ip_port", "criminalip_ip_vulnerability",
		"criminalip_ip_malicious", "criminalip_ip_suspicious", "criminalip_ip_privacy_threat", "criminalip_ip_vpn",
		"criminalip_ip_hosting", "criminalip_dns_server_safety"} {
		table := p.TableMap[name]
		kc := table.List.KeyColumns.Find("ip")
		if kc == nil || kc.Require != plugin.Required {
			t.Errorf("%s: ip must be a required key column", name)
		}
	}
}

func TestNormalizeIPv4(t *testing.T) {
	good := map[string]string{"8.8.8.8": "8.8.8.8", " 1.1.1.1 ": "1.1.1.1", "185.220.101.1/32": "185.220.101.1"}
	for in, want := range good {
		got, err := normalizeIPv4(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, in := range []string{"2001:4860:4860::8888", "::ffff:8.8.8.8", "8.8.8.0/24", "not-an-ip", ""} {
		if _, err := normalizeIPv4(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
}

func TestIPTableSummary(t *testing.T) {
	table := tableCriminalIPIP(context.Background())
	sum := decodeIPFixture[ipSummary](t, "v1_asset_ip_summary_185.220.101.1.json")
	vals := rowValues(t, table, nil, sum)
	wantValue(t, vals, "ip", "185.220.101.1")
	wantValue(t, vals, "score_inbound", "Critical")
	wantValue(t, vals, "country_code", "DE")
	wantValue(t, vals, "as_no", int64(60729))

	// 8.8.8.8 has region, city and postal_code null in the API: they must be
	// SQL null, not empty strings.
	vals = rowValues(t, table, nil, decodeIPFixture[ipSummary](t, "v1_asset_ip_summary_8.8.8.8.json"))
	wantValue(t, vals, "region", nil)
	wantValue(t, vals, "city", nil)
	wantValue(t, vals, "postal_code", nil)
	wantValue(t, vals, "country", "United States")

	rs := decodeIPFixture[ipReportSummary](t, "v1_asset_ip_report_summary_185.220.101.1.json")
	vals = rowValues(t, table, getIPReportSummary, rs)
	wantValue(t, vals, "is_malicious", true)
	wantValue(t, vals, "is_tor", true)
	wantValue(t, vals, "is_vpn", false)
	wantValue(t, vals, "abuse_record_count", int64(37))
	wantValue(t, vals, "hostname", "berlin01.tor-exit.artikel10.org")
	if vals["representative_domain"] != (*string)(nil) && vals["representative_domain"] != nil {
		t.Errorf("representative_domain should be null, got %#v", vals["representative_domain"])
	}
}

func reportResult(t *testing.T, fixture string, full bool) *ipReportResult {
	return &ipReportResult{Full: full, Report: decodeIPFixture[ipReport](t, fixture)}
}

func TestIPReportTable(t *testing.T) {
	res := reportResult(t, "v2_asset_ip_report_185.220.101.1.json", true)
	vals := rowValues(t, tableCriminalIPIPReport(context.Background()), nil, &ipReportRow{Full: res.Full, ipReport: *res.Report})
	wantValue(t, vals, "ip", "185.220.101.1")
	wantValue(t, vals, "full_report", true)
	wantValue(t, vals, "is_tor", true)
	wantValue(t, vals, "is_snort", true)
	wantValue(t, vals, "ids_count", 10)
	wantValue(t, vals, "user_search_count", int64(18))
	wantValue(t, vals, "timestamp", time.Date(2026, 10, 22, 21, 30, 55, 0, time.UTC))
}

func TestIPPortRows(t *testing.T) {
	res := reportResult(t, "v2_asset_ip_report_34.22.91.145_with_cves.json", false)
	rows := ipPortRows(res)
	if len(rows) != 3 {
		t.Fatalf("want 3 port rows from trimmed fixture, got %d", len(rows))
	}
	table := tableCriminalIPIPPort(context.Background())
	vals := rowValues(t, table, nil, rows[1])
	wantValue(t, vals, "ip", "34.22.91.145")
	wantValue(t, vals, "full_report", false)
	wantValue(t, vals, "port", int64(443))
	wantValue(t, vals, "socket", "tcp")
	wantValue(t, vals, "sdn_common_name", "*.tachyonnews.com")
	wantValue(t, vals, "confirmed_time", time.Date(2026, 10, 22, 9, 7, 15, 0, time.UTC))
	// null strings in the API must stay null, not ""
	vals = rowValues(t, table, nil, rows[0])
	if v := vals["jarm_hash"]; v != nil && v != (*string)(nil) {
		t.Errorf("jarm_hash should be null, got %#v", v)
	}
	if rows[0].Software[0].Product != "Apache" {
		t.Errorf("software not decoded: %+v", rows[0].Software)
	}
}

func TestIPVulnerabilityRows(t *testing.T) {
	res := reportResult(t, "v2_asset_ip_report_34.22.91.145_with_cves.json", true)
	rows := ipVulnRows(res)
	if len(rows) != 3 {
		t.Fatalf("want 3 CVE rows, got %d", len(rows))
	}
	vals := rowValues(t, tableCriminalIPIPVulnerability(context.Background()), nil, rows[0])
	wantValue(t, vals, "cve_id", "CVE-2026-93546")
	wantValue(t, vals, "cvssv3_score", 8.8)
	wantValue(t, vals, "app_name", "Apache")
	wantValue(t, vals, "exploit_count", 0)
	if vals["is_vuln"] != (*bool)(nil) && vals["is_vuln"] != nil {
		t.Errorf("is_vuln \"\" should be null, got %#v", vals["is_vuln"])
	}
	if rows[0].ListChild == nil {
		t.Error("list_child not decoded")
	}
}

func TestIPMaliciousTrailingSpaceKey(t *testing.T) {
	m := decodeIPFixture[ipMalicious](t, "v3_feature_ip_malicious-info_185.220.101.1.json")
	vals := rowValues(t, tableCriminalIPIPMalicious(context.Background()), nil, m)
	wantValue(t, vals, "is_malicious", true)
	wantValue(t, vals, "hostname", "berlin01.tor-exit.artikel10.org")
	wantValue(t, vals, "hostname_time", time.Date(2026, 7, 25, 7, 0, 17, 0, time.UTC))
	wantValue(t, vals, "ids_count", 10)
	wantValue(t, vals, "scanning_record_count", 20)

	// and the fixed spelling, should the API ever correct it
	var fixed ipMalicious
	_ = json.Unmarshal([]byte(`{"std_info":{"hostname_dtime":"2026-01-02 03:04:05"}}`), &fixed)
	if fixed.HostnameSeen() != "2026-01-02 03:04:05" {
		t.Errorf("fallback key not read: %q", fixed.HostnameSeen())
	}
}

func TestIPSuspicious(t *testing.T) {
	s := decodeIPFixture[ipSuspicious](t, "v3_feature_ip_suspicious-info_185.220.101.1.json")
	vals := rowValues(t, tableCriminalIPIPSuspicious(context.Background()), nil, s)
	wantValue(t, vals, "score_inbound", "Critical")
	wantValue(t, vals, "abuse_record_count", int64(37))
	wantValue(t, vals, "is_tor", true)
	if v := vals["representative_domain"]; v != nil {
		t.Errorf("empty representative_domain should be null, got %#v", v)
	}
}

func TestSmallIPTables(t *testing.T) {
	ctx := context.Background()
	pt := decodeIPFixture[ipPrivacyThreat](t, "v2_feature_ip_privacy-threat_8.8.8.8.json")
	vals := rowValues(t, tableCriminalIPIPPrivacyThreat(ctx), nil, pt)
	wantValue(t, vals, "other_ports_count", 2)
	wantValue(t, vals, "webcam_count", 0)

	vpn := decodeIPFixture[ipVPN](t, "v1_ip_vpn_185.220.101.1.json")
	vals = rowValues(t, tableCriminalIPIPVPN(ctx), nil, vpn)
	wantValue(t, vals, "is_tor", true)
	wantValue(t, vals, "is_vpn", false)

	h := decodeIPFixture[ipHosting](t, "v1_ip_hosting_8.8.8.8.json")
	vals = rowValues(t, tableCriminalIPIPHosting(ctx), nil, h)
	wantValue(t, vals, "is_hosting", true)
	wantValue(t, vals, "cloud_service", "Google")
	wantValue(t, vals, "cloud_ip_range", "8.8.8.0/24")
	if v := vals["as_name_hosting_match"]; v != nil {
		t.Errorf("as_name_hosting_match should be null, got %#v", v)
	}

	dns := decodeIPFixture[dnsServerSafety](t, "v1_feature_ip_is_safe_dns_server_1.1.1.1.json")
	vals = rowValues(t, tableCriminalIPDNSServerSafety(ctx), nil, dns)
	wantValue(t, vals, "is_safe_dns_server", false)
	wantValue(t, vals, "opened_unusual_port", true)
}

func TestAccountDropsAPIKey(t *testing.T) {
	raw := readSearchFixture(t, "user_me.json")
	var env struct {
		Data accountInfo `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env.Data)
	if json.Valid(b) && string(b) != "" && containsKey(b) {
		t.Fatalf("account row carries api_key: %s", b)
	}
	vals := rowValues(t, tableCriminalIPAccount(context.Background()), nil, &env.Data)
	wantValue(t, vals, "email", "user@example.com")
	wantValue(t, vals, "membership_date", time.Date(2026, 10, 19, 5, 30, 0, 0, time.UTC))
}

func containsKey(b []byte) bool {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k := range m {
		if k == "api_key" || k == "APIKey" {
			return true
		}
	}
	return false
}
