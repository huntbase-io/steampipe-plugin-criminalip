package criminalip

import (
	"context"
	"net/url"
	"strings"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// domainQuickData is the data payload of the /v1/domain/quick/*/view
// lookups. On a miss the API returns status 200, data {} and a
// "No Data (domain: ...)" message.
type domainQuickData struct {
	CallCount apiclient.FlexString `json:"call_count"`
	Domain    apiclient.FlexString `json:"domain"`
	RegDtime  apiclient.FlexString `json:"reg_dtime"`
	Result    apiclient.FlexString `json:"result"`
	Type      apiclient.FlexString `json:"type"`
}

// domainQuickLookup is the result of one quick lookup.
type domainQuickLookup struct {
	Found bool
	Data  domainQuickData
}

// domainQuickRow is the row for one domain: the hash/view verdict. The
// malicious and trusted list lookups are separate hydrates, so they are
// only called when their columns are selected.
type domainQuickRow struct {
	Domain string
	Hash   domainQuickLookup
}

func tableCriminalIPDomainQuick(_ context.Context) *plugin.Table {
	str := func(field string) *transform.ColumnTransforms {
		return transform.FromField(field).Transform(emptyStringToNil)
	}
	return &plugin.Table{
		Name:        "criminalip_domain_quick",
		Description: "Fast, synchronous domain verdicts from Criminal IP's quick lookups (hash, malicious list and trusted list). Never starts a domain scan.",
		List: &plugin.ListConfig{
			Hydrate:    listDomainQuick,
			KeyColumns: plugin.SingleColumn("domain"),
		},
		// The API rejects concurrent calls from one key ("unable to call api at
		// the same time"), so the trusted lookup waits for the malicious one.
		HydrateConfig: []plugin.HydrateConfig{
			{Func: getDomainQuickMalicious},
			{Func: getDomainQuickTrusted, Depends: []plugin.HydrateFunc{getDomainQuickMalicious}},
		},
		Columns: []*plugin.Column{
			{Name: "domain", Type: proto.ColumnType_STRING, Transform: transform.FromField("Domain"), Description: "The domain name to look up, for example google.com."},

			// /v1/domain/quick/hash/view
			{Name: "found", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Hash.Found"), Description: "True if the quick hash lookup knows the domain. False means the API answered 'No Data'."},
			{Name: "result", Type: proto.ColumnType_STRING, Transform: str("Hash.Data.Result"), Description: "The quick verdict for the domain, for example safe or malicious. Compare it case-insensitively."},
			{Name: "type", Type: proto.ColumnType_STRING, Transform: str("Hash.Data.Type"), Description: "The category behind the verdict, for example trusted-domain, searchengine or phishing."},
			{Name: "call_count", Type: proto.ColumnType_INT, Transform: transform.FromField("Hash.Data.CallCount").Transform(flexStringToInt), Description: "How many times the domain has been looked up."},
			{Name: "reg_dtime", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("Hash.Data.RegDtime").Transform(naiveTimeToTimestamp), Description: "When the domain entry was registered (API time without a timezone, assumed UTC)."},

			// /v1/domain/quick/malicious/view
			{Name: "is_malicious_listed", Type: proto.ColumnType_BOOL, Hydrate: getDomainQuickMalicious, Transform: transform.FromField("Found"), Description: "True if the domain is on Criminal IP's malicious domain list. Costs one extra API call."},
			{Name: "malicious_type", Type: proto.ColumnType_STRING, Hydrate: getDomainQuickMalicious, Transform: str("Data.Type"), Description: "The malicious-list category, for example phishing."},
			{Name: "malicious_call_count", Type: proto.ColumnType_INT, Hydrate: getDomainQuickMalicious, Transform: transform.FromField("Data.CallCount").Transform(flexStringToInt), Description: "The malicious-list lookup count."},
			{Name: "malicious_reg_dtime", Type: proto.ColumnType_TIMESTAMP, Hydrate: getDomainQuickMalicious, Transform: transform.FromField("Data.RegDtime").Transform(naiveTimeToTimestamp), Description: "When the domain was added to the malicious list (assumed UTC)."},

			// /v1/domain/quick/trusted/view
			{Name: "is_trusted_listed", Type: proto.ColumnType_BOOL, Hydrate: getDomainQuickTrusted, Transform: transform.FromField("Found"), Description: "True if the domain is on Criminal IP's trusted domain list. Costs one extra API call."},
			{Name: "trusted_type", Type: proto.ColumnType_STRING, Hydrate: getDomainQuickTrusted, Transform: str("Data.Type"), Description: "The trusted-list category, for example trusted-domain or searchengine."},
			{Name: "trusted_call_count", Type: proto.ColumnType_INT, Hydrate: getDomainQuickTrusted, Transform: transform.FromField("Data.CallCount").Transform(flexStringToInt), Description: "The trusted-list lookup count."},
			{Name: "trusted_reg_dtime", Type: proto.ColumnType_TIMESTAMP, Hydrate: getDomainQuickTrusted, Transform: transform.FromField("Data.RegDtime").Transform(naiveTimeToTimestamp), Description: "When the domain was added to the trusted list (assumed UTC)."},
		},
	}
}

// domainQual returns the raw "domain" qual (returned unchanged in the row so
// that Postgres's re-check of the WHERE clause matches) and the normalised
// form sent to the API.
func domainQual(d *plugin.QueryData) (raw, normalized string) {
	raw = d.EqualsQualString("domain")
	normalized = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	return raw, normalized
}

// quickLookup calls one /v1/domain/quick/{kind}/view endpoint.
func quickLookup(ctx context.Context, c *apiclient.Client, kind, domain string) (*domainQuickLookup, error) {
	var env apiclient.Envelope[domainQuickData]
	if err := c.Get(ctx, "/v1/domain/quick/"+kind+"/view", url.Values{"domain": {domain}}, &env); err != nil {
		return nil, err
	}
	return quickLookupFromEnvelope(&env), nil
}

func quickLookupFromEnvelope(env *apiclient.Envelope[domainQuickData]) *domainQuickLookup {
	found := !apiclient.IsNoData(env.Message) && env.Data != (domainQuickData{})
	return &domainQuickLookup{Found: found, Data: env.Data}
}

func listDomainQuick(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	raw, domain := domainQual(d)
	if domain == "" {
		return nil, nil
	}
	c, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_domain_quick.listDomainQuick", "connection_error", err)
		return nil, err
	}
	hash, err := quickLookup(ctx, c, "hash", domain)
	if err != nil {
		if apiclient.IsBadRequest(err) {
			// Not a valid domain: no row rather than a failed query.
			plugin.Logger(ctx).Warn("criminalip_domain_quick.listDomainQuick", "domain", domain, "bad_request", err)
			return nil, nil
		}
		plugin.Logger(ctx).Error("criminalip_domain_quick.listDomainQuick", "api_error", err)
		return nil, err
	}
	d.StreamListItem(ctx, domainQuickRow{Domain: raw, Hash: *hash})
	return nil, nil
}

func getDomainQuickMalicious(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	return hydrateDomainQuick(ctx, d, h, "malicious")
}

func getDomainQuickTrusted(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	return hydrateDomainQuick(ctx, d, h, "trusted")
}

func hydrateDomainQuick(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData, kind string) (interface{}, error) {
	row, ok := h.Item.(domainQuickRow)
	if !ok {
		return nil, nil
	}
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(row.Domain)), ".")
	c, err := connect(ctx, d)
	if err != nil {
		return nil, err
	}
	res, err := quickLookup(ctx, c, kind, domain)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_domain_quick.hydrateDomainQuick", "kind", kind, "api_error", err)
		return nil, err
	}
	return res, nil
}
