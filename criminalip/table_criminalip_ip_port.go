package criminalip

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type ipPortRow struct {
	IP   string
	Full bool
	ipPort
}

func ipPortRows(res *ipReportResult) []*ipPortRow {
	if res == nil || res.Report == nil {
		return nil
	}
	rows := make([]*ipPortRow, 0, len(res.Report.Port.Data))
	for _, p := range res.Report.Port.Data {
		rows = append(rows, &ipPortRow{IP: res.Report.IP, Full: res.Full, ipPort: p})
	}
	return rows
}

func tableCriminalIPIPPort(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_ip_port",
		Description: "Open ports seen on an IPv4 address, one row per port, with banner, software, OS and TLS details.",
		List: &plugin.ListConfig{
			Hydrate:    listIPPorts,
			KeyColumns: ipReportKeyColumns(),
		},
		Columns: []*plugin.Column{
			ipColumn(),
			fullColumn(),
			{Name: "port", Type: proto.ColumnType_INT, Transform: transform.FromField("OpenPortNo"), Description: "Port number."},
			{Name: "socket", Type: proto.ColumnType_STRING, Description: "Transport: tcp or udp."},
			{Name: "protocol", Type: proto.ColumnType_STRING, Transform: transform.FromField("Protocol").Transform(emptyStringToNil), Description: "Application protocol, for example HTTP, HTTPS, SSH or DNS."},
			{Name: "port_status", Type: proto.ColumnType_STRING, Description: "Port status, for example open."},
			{Name: "is_vulnerability", Type: proto.ColumnType_BOOL, Description: "True if the service on this port has known vulnerabilities."},
			{Name: "confirmed_time", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromField("ConfirmedTime").Transform(naiveTimeToTimestamp), Description: "When the port was last confirmed open (assumed UTC)."},
			{Name: "software", Type: proto.ColumnType_JSON, Description: "Detected software as [{product, version}]."},
			{Name: "operating_systems", Type: proto.ColumnType_JSON, Description: "Detected operating systems as [{product, version}]."},
			{Name: "technologies", Type: proto.ColumnType_JSON, Description: "Detected web technologies as [{tech_name, tech_version, tech_logo_url}]."},
			{Name: "tags", Type: proto.ColumnType_JSON, Description: "Tags for the port."},
			{Name: "banner", Type: proto.ColumnType_STRING, Description: "Raw service banner."},
			{Name: "dns_names", Type: proto.ColumnType_STRING, Transform: transform.FromField("DNSNames").Transform(emptyStringToNil), Description: "DNS names from the TLS certificate (comma separated)."},
			{Name: "sdn_common_name", Type: proto.ColumnType_STRING, Transform: transform.FromField("SDNCommonName").Transform(emptyStringToNil), Description: "Common name of the TLS certificate subject."},
			{Name: "jarm_hash", Type: proto.ColumnType_STRING, Transform: transform.FromField("JarmHash").Transform(emptyStringToNil), Description: "JARM TLS fingerprint."},
			{Name: "ssl_info_raw", Type: proto.ColumnType_STRING, Transform: transform.FromField("SSLInfoRaw").Transform(emptyStringToNil), Description: "Raw TLS certificate text."},
		},
	}
}

func listIPPorts(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	res, err := fetchIPReport(ctx, d, h)
	if err != nil {
		plugin.Logger(ctx).Error("criminalip_ip_port.listIPPorts", "api_error", err)
		return nil, err
	}
	for _, row := range ipPortRows(res) {
		d.StreamListItem(ctx, row)
		if d.RowsRemaining(ctx) == 0 {
			break
		}
	}
	return nil, nil
}
