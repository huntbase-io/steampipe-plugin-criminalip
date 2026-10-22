package criminalip

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

// Default number of search records returned when the query has no SQL LIMIT.
const defaultMaxSearchResults = 100

type criminalipConfig struct {
	APIKey           *string `hcl:"api_key"`
	BaseURL          *string `hcl:"base_url"`
	MaxSearchResults *int    `hcl:"max_search_results"`
}

func ConfigInstance() interface{} {
	return &criminalipConfig{}
}

// GetConfig retrieves and casts the connection config from query data.
func GetConfig(connection *plugin.Connection) criminalipConfig {
	if connection == nil || connection.Config == nil {
		return criminalipConfig{}
	}
	config, _ := connection.Config.(criminalipConfig)
	return config
}
