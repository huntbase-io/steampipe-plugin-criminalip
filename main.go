package main

import (
	"github.com/huntbase-io/steampipe-plugin-criminalip/criminalip"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: criminalip.Plugin})
}
