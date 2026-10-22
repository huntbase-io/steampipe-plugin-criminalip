package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFlexString(t *testing.T) {
	var v struct {
		A FlexString `json:"a"`
		B FlexString `json:"b"`
		C FlexString `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":73944665,"b":"73944665","c":null}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A != "73944665" || v.B != "73944665" || v.C != "" {
		t.Fatalf("got %+v", v)
	}
}

func TestFlexBool(t *testing.T) {
	cases := map[string]*bool{`true`: ptr(true), `false`: ptr(false), `"True"`: ptr(true), `"false"`: ptr(false), `""`: nil, `null`: nil}
	for in, want := range cases {
		var f FlexBool
		if err := json.Unmarshal([]byte(in), &f); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got := f.Ptr()
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestParseTime(t *testing.T) {
	want := time.Date(2026, 10, 22, 21, 33, 56, 0, time.UTC)
	if got, ok := ParseTime("2026-10-22 21:33:56"); !ok || !got.Equal(want) {
		t.Fatalf("got %v %v", got, ok)
	}
	if got, ok := ParseTime("2026-05-13"); !ok || got.Day() != 13 {
		t.Fatalf("date only: %v %v", got, ok)
	}
	if got, ok := ParseTime("Wed, 13 May 2026 00:00:00 GMT"); !ok || got.Month() != time.May {
		t.Fatalf("rfc1123: %v %v", got, ok)
	}
	if _, ok := ParseTime(""); ok {
		t.Fatal("empty should not parse")
	}
	if _, ok := ParseTime("garbage"); ok {
		t.Fatal("garbage should not parse")
	}
}

func TestSearchEnvelopeDecodesFixture(t *testing.T) {
	var env Envelope[SearchData[map[string]any]]
	if err := json.Unmarshal(fixture(t, "v2_banner_search_openssh_kr.json"), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Count != 283716 || len(env.Data.Result) == 0 || len(env.Data.Groups) != 1 {
		t.Fatalf("bad decode: count=%d results=%d", env.Data.Count, len(env.Data.Result))
	}
	if f := env.Data.Groups[0].Filters; len(f) != 3 || f[0].Key != "product" {
		t.Fatalf("bad groups: %+v", env.Data.Groups)
	}
}

func pages(sizes ...int) PageFetcher[int] {
	return func(_ context.Context, offset int) (*Page[int], error) {
		// find page by cumulative offset
		cum := 0
		for _, n := range sizes {
			if offset == cum {
				recs := make([]int, n)
				for i := range recs {
					recs[i] = offset + i
				}
				return &Page[int]{Records: recs, Total: -1}, nil
			}
			cum += n
		}
		return &Page[int]{Total: -1}, nil
	}
}

func TestPaginateStopsAtMaxRecords(t *testing.T) {
	var got []int
	calls, err := Paginate(context.Background(), pages(10, 10, 10, 10), PaginateOptions{MaxRecords: 15, PageSize: 10}, func(i int) bool {
		got = append(got, i)
		return true
	})
	if err != nil || calls != 2 || len(got) != 15 || got[14] != 14 {
		t.Fatalf("calls=%d got=%v err=%v", calls, got, err)
	}
}

func TestPaginateStopsOnShortPage(t *testing.T) {
	calls, _ := Paginate(context.Background(), pages(100, 37, 100), PaginateOptions{MaxRecords: 1000, PageSize: 100}, func(int) bool { return true })
	if calls != 2 {
		t.Fatalf("calls=%d, want 2", calls)
	}
}

func TestPaginateStopsAtTotal(t *testing.T) {
	fetch := func(_ context.Context, offset int) (*Page[int], error) {
		return &Page[int]{Records: make([]int, 10), Total: 25}, nil
	}
	calls, _ := Paginate(context.Background(), fetch, PaginateOptions{MaxRecords: 1000}, func(int) bool { return true })
	if calls != 3 {
		t.Fatalf("calls=%d, want 3", calls)
	}
}

func TestPaginateStopsWhenEmitDeclines(t *testing.T) {
	n := 0
	calls, _ := Paginate(context.Background(), pages(10, 10), PaginateOptions{MaxRecords: 100, PageSize: 10}, func(int) bool { n++; return n < 3 })
	if calls != 1 || n != 3 {
		t.Fatalf("calls=%d n=%d", calls, n)
	}
}

func TestPaginateNeverPastMaxOffset(t *testing.T) {
	var last int
	fetch := func(_ context.Context, offset int) (*Page[int], error) {
		last = offset
		return &Page[int]{Records: make([]int, 100), Total: 1_000_000}, nil
	}
	calls, _ := Paginate(context.Background(), fetch, PaginateOptions{MaxRecords: 1_000_000, PageSize: 100}, func(int) bool { return true })
	if last > MaxOffset || calls != 100 {
		t.Fatalf("last offset %d, calls %d", last, calls)
	}
}

func TestPaginateRequiresBound(t *testing.T) {
	if _, err := Paginate(context.Background(), pages(1), PaginateOptions{}, func(int) bool { return true }); !errors.Is(err, ErrNoBound) {
		t.Fatalf("want ErrNoBound, got %v", err)
	}
}
