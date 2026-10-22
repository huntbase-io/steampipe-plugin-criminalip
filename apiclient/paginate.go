package apiclient

import (
	"context"
	"errors"
)

// MaxOffset is the largest offset the search endpoints accept. At most 10,000
// records (offset 0..9900 plus one page) are reachable per query.
const MaxOffset = 9900

// MaxReachableRecords is the hard ceiling on records per search query.
const MaxReachableRecords = 10000

// Page is one page returned by a PageFetcher.
type Page[T any] struct {
	Records []T
	// Total is the server-reported total match count, or -1 if the endpoint's
	// count is not a total (asset search reports the page size instead).
	Total int
}

// PageFetcher fetches the page that starts at the given record offset.
type PageFetcher[T any] func(ctx context.Context, offset int) (*Page[T], error)

// PaginateOptions controls Paginate. MaxRecords must be > 0: Paginate never
// pages without a bound, because every call can cost API credits.
type PaginateOptions struct {
	// MaxRecords is the maximum number of records to emit (capped at
	// MaxReachableRecords).
	MaxRecords int
	// PageSize is the expected full page size (banner/exploit 10, asset and
	// domain reports 100). When > 0, a shorter page ends pagination.
	PageSize int
	// StartOffset is the first record offset (normally 0).
	StartOffset int
}

// ErrNoBound is returned when MaxRecords is not positive.
var ErrNoBound = errors.New("criminalip: Paginate requires MaxRecords > 0")

// Paginate fetches pages with offset += len(page) and calls emit for each
// record. It stops when:
//   - emit returns false (for example the SQL LIMIT was reached),
//   - MaxRecords records were emitted,
//   - a page is empty, or shorter than PageSize,
//   - the offset reaches Total, or the next offset would exceed MaxOffset.
//
// It returns the number of API calls made.
func Paginate[T any](ctx context.Context, fetch PageFetcher[T], opts PaginateOptions, emit func(T) bool) (int, error) {
	if opts.MaxRecords <= 0 {
		return 0, ErrNoBound
	}
	maxRecords := min(opts.MaxRecords, MaxReachableRecords)
	offset := max(opts.StartOffset, 0)
	emitted, calls := 0, 0

	for offset <= MaxOffset {
		if err := ctx.Err(); err != nil {
			return calls, err
		}
		page, err := fetch(ctx, offset)
		calls++
		if err != nil {
			return calls, err
		}
		if page == nil || len(page.Records) == 0 {
			return calls, nil
		}
		for _, r := range page.Records {
			if !emit(r) {
				return calls, nil
			}
			emitted++
			if emitted >= maxRecords {
				return calls, nil
			}
		}
		offset += len(page.Records)
		if opts.PageSize > 0 && len(page.Records) < opts.PageSize {
			return calls, nil
		}
		if page.Total >= 0 && offset >= page.Total {
			return calls, nil
		}
	}
	return calls, nil
}
