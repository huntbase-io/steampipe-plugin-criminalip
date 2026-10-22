package criminalip

import (
	"context"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// accountInfo deliberately has no api_key field: /v1/user/me echoes the full
// API key, and decoding into this struct drops it before it can reach a row,
// a log line or the query cache.
type accountInfo struct {
	AccountType    string `json:"account_type"`
	CompanyName    string `json:"company_name"`
	Email          string `json:"email"`
	LastAccessDate string `json:"last_access_date"`
	MembershipDate string `json:"membership_date"`
	Name           string `json:"name"`
}

func tableCriminalIPAccount(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_account",
		Description: "The Criminal IP account that owns the configured API key.",
		List: &plugin.ListConfig{
			Hydrate: listAccount,
		},
		Columns: []*plugin.Column{
			{Name: "email", Type: proto.ColumnType_STRING, Description: "Email address of the account."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Display name of the account."},
			{Name: "company_name", Type: proto.ColumnType_STRING, Description: "Company name registered on the account."},
			{Name: "account_type", Type: proto.ColumnType_STRING, Description: "How the account signs in, for example google_social."},
			{Name: "membership_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("MembershipDate").Transform(naiveTimeToTimestamp), Description: "When the account was created (API time, assumed UTC)."},
			{Name: "last_access_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastAccessDate").Transform(naiveTimeToTimestamp), Description: "When the account was last used (API time, assumed UTC)."},
		},
	}
}

func getAccount(ctx context.Context, c *apiclient.Client) (*accountInfo, error) {
	var env apiclient.Envelope[accountInfo]
	if err := c.Post(ctx, "/v1/user/me", nil, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

func listAccount(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	c, err := connect(ctx, d)
	if err != nil {
		return nil, err
	}
	acct, err := getAccount(ctx, c)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_account.listAccount", "api_error", err)
		return nil, err
	}
	d.StreamListItem(ctx, acct)
	return nil, nil
}
