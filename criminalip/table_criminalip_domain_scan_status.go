package criminalip

import (
	"context"
	"strconv"

	"github.com/huntbase-io/steampipe-plugin-criminalip/apiclient"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type domainScanStatusData struct {
	ScanPercentage apiclient.FlexString `json:"scan_percentage"`
}

type domainScanStatusRow struct {
	ScanID         int64
	ScanPercentage *int64
	Status         string
}

func tableCriminalIPDomainScanStatus(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "criminalip_domain_scan_status",
		Description: "The progress of a Criminal IP domain scan, by scan ID. Read-only: it never starts a scan.",
		List: &plugin.ListConfig{
			Hydrate:    listDomainScanStatus,
			KeyColumns: plugin.SingleColumn("scan_id"),
		},
		Columns: []*plugin.Column{
			{Name: "scan_id", Type: proto.ColumnType_INT, Transform: transform.FromField("ScanID"), Description: "The scan ID."},
			{Name: "scan_percentage", Type: proto.ColumnType_INT, Transform: transform.FromField("ScanPercentage"), Description: "Scan progress from 0 to 100. -1 means the scan failed and -2 means the domain does not exist."},
			{Name: "status", Type: proto.ColumnType_STRING, Transform: transform.FromField("Status"), Description: "The progress as a word: in_progress, complete, failed or domain_not_found."},
		},
	}
}

func listDomainScanStatus(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
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
		plugin.Logger(ctx).Error("criminalip_domain_scan_status.listDomainScanStatus", "connection_error", err)
		return nil, err
	}
	var env apiclient.Envelope[domainScanStatusData]
	if err := c.Get(ctx, "/v1/domain/status/"+strconv.FormatInt(scanID, 10), nil, &env); err != nil {
		if apiclient.IsNotFound(err) {
			// status 420: no scan with this ID.
			return nil, nil
		}
		plugin.Logger(ctx).Error("criminalip_domain_scan_status.listDomainScanStatus", "api_error", err)
		return nil, err
	}
	d.StreamListItem(ctx, newDomainScanStatusRow(scanID, env.Data))
	return nil, nil
}

func newDomainScanStatusRow(scanID int64, data domainScanStatusData) domainScanStatusRow {
	row := domainScanStatusRow{ScanID: scanID}
	p, err := strconv.ParseInt(string(data.ScanPercentage), 10, 64)
	if err != nil {
		return row
	}
	row.ScanPercentage = &p
	switch {
	case p == -1:
		row.Status = "failed"
	case p == -2:
		row.Status = "domain_not_found"
	case p >= 100:
		row.Status = "complete"
	case p >= 0:
		row.Status = "in_progress"
	}
	return row
}
