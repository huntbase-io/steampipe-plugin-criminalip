package criminalip

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
	"github.com/turbot/steampipe-plugin-sdk/v5/rate_limiter"
)

const pluginVersion = "0.1.0"

// Plugin creates this (criminalip) plugin.
func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name:             "steampipe-plugin-criminalip",
		DefaultTransform: transform.FromGo(),
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
		},
		DefaultRetryConfig: retryConfig(),
		DefaultGetConfig: &plugin.GetConfig{
			IgnoreConfig: &plugin.IgnoreConfig{ShouldIgnoreErrorFunc: isNotFoundError},
		},
		// Criminal IP publishes no rate-limit headers, and rejects concurrent
		// calls with the same key ("unable to call api at the same time").
		// Users can override this with a `limiter` block in their .spc file.
		RateLimiters: []*rate_limiter.Definition{
			{
				Name:           "criminalip_api",
				FillRate:       2,
				BucketSize:     5,
				MaxConcurrency: 1,
				Scope:          []string{"connection"},
			},
		},
		TableMap: map[string]*plugin.Table{
			"criminalip_account":            tableCriminalIPAccount(ctx),
			"criminalip_asset_search":       tableCriminalIPAssetSearch(ctx),
			"criminalip_banner_search":      tableCriminalIPBannerSearch(ctx),
			"criminalip_banner_stats":       tableCriminalIPBannerStats(ctx),
			"criminalip_domain_quick":       tableCriminalIPDomainQuick(ctx),
			"criminalip_domain_report":      tableCriminalIPDomainReport(ctx),
			"criminalip_domain_report_list": tableCriminalIPDomainReportList(ctx),
			"criminalip_domain_scan_status": tableCriminalIPDomainScanStatus(ctx),
			"criminalip_exploit_search":     tableCriminalIPExploitSearch(ctx),
			"criminalip_dns_server_safety":  tableCriminalIPDNSServerSafety(ctx),
			"criminalip_ip":                 tableCriminalIPIP(ctx),
			"criminalip_ip_hosting":         tableCriminalIPIPHosting(ctx),
			"criminalip_ip_malicious":       tableCriminalIPIPMalicious(ctx),
			"criminalip_ip_port":            tableCriminalIPIPPort(ctx),
			"criminalip_ip_privacy_threat":  tableCriminalIPIPPrivacyThreat(ctx),
			"criminalip_ip_report":          tableCriminalIPIPReport(ctx),
			"criminalip_ip_suspicious":      tableCriminalIPIPSuspicious(ctx),
			"criminalip_ip_vpn":             tableCriminalIPIPVPN(ctx),
			"criminalip_ip_vulnerability":   tableCriminalIPIPVulnerability(ctx),
		},
	}
	return p
}
