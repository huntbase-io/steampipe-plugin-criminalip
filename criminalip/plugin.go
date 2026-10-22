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
		// Criminal IP publishes no rate-limit headers; stay polite by default.
		// Users can override this with a `limiter` block in their .spc file.
		RateLimiters: []*rate_limiter.Definition{
			{
				Name:       "criminalip_api",
				FillRate:   2,
				BucketSize: 5,
				Scope:      []string{"connection"},
			},
		},
		TableMap: map[string]*plugin.Table{
			"criminalip_account": tableCriminalIPAccount(ctx),
		},
	}
	return p
}
