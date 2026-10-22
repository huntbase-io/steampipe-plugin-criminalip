package apiclient

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Envelope is the {status, message, data} wrapper used by search, domain and
// user endpoints. IP endpoints return flat objects instead.
type Envelope[T any] struct {
	Status    int    `json:"status"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp,omitempty"`
	Data      T      `json:"data"`
}

// SearchData is the data payload of banner, asset and exploit searches.
// For banner and exploit search Count is the total number of matches; for
// asset search it is the number of records on the page.
type SearchData[T any] struct {
	Groups []QueryGroup `json:"groups"`
	Count  int          `json:"count"`
	Result []T          `json:"result"`
}

// QueryGroup is the server's parse of one OR-group of a search query.
type QueryGroup struct {
	Keywords []struct {
		Keyword string `json:"keyword"`
		Negate  bool   `json:"negate"`
	} `json:"keywords"`
	Filters []struct {
		Key    string `json:"key"`
		Value  string `json:"value"`
		Negate bool   `json:"negate"`
	} `json:"filters"`
}

// Section is the {count, data} shape used for list sections of IP reports.
// Without full=true the API caps Data at 20 items and Count equals len(Data).
type Section[T any] struct {
	Count int `json:"count"`
	Data  []T `json:"data"`
}

// Product is an entry of the v2/v3 software[] and operating_systems[] arrays.
type Product struct {
	Product string `json:"product"`
	Version string `json:"version"`
}

// FlexString decodes a JSON string, number or bool into a string. Use it for
// fields whose type varies between endpoints (scan_id, status_code).
// null decodes to "".
type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = FlexString(s)
		return nil
	}
	*f = FlexString(string(b))
	return nil
}

// FlexBool decodes a JSON bool, "true"/"false" (any case), "" or null.
// Valid is false for "", null and unrecognised values.
type FlexBool struct {
	Value bool
	Valid bool
}

func (f *FlexBool) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = FlexBool{}
	switch t := v.(type) {
	case bool:
		*f = FlexBool{Value: t, Valid: true}
	case string:
		if parsed, err := strconv.ParseBool(strings.TrimSpace(t)); err == nil {
			*f = FlexBool{Value: parsed, Valid: true}
		}
	case float64:
		*f = FlexBool{Value: t != 0, Valid: true}
	}
	return nil
}

func (f FlexBool) MarshalJSON() ([]byte, error) {
	if !f.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(f.Value)
}

// Ptr returns nil when the value is not valid, for use in Steampipe columns.
func (f FlexBool) Ptr() *bool {
	if !f.Valid {
		return nil
	}
	v := f.Value
	return &v
}

// naive time layouts used by the API. None carry a timezone.
var timeLayouts = []string{
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02",
	time.RFC1123, // scanning_record.log_date: "Wed, 13 May 2026 00:00:00 GMT"
	time.RFC3339,
}

// ParseTime parses a timezone-less API timestamp ("YYYY-MM-DD HH:MM:SS" or
// "YYYY-MM-DD") as UTC. It returns ok=false for empty or unparsable input.
// Note: /v1/domain/reports/personal appears to use KST (UTC+9), not UTC.
func ParseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
