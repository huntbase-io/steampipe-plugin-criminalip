// Package criminalip implements the Steampipe plugin for the Criminal IP
// threat-intelligence API.
//
// HTTP access goes through the apiclient package (see its package doc). Table
// code should use these helpers from utils.go:
//
//   - connect(ctx, d) returns the cached *apiclient.Client for the connection
//     (api_key from config, falling back to CRIMINALIP_API_KEY).
//   - streamSearch(ctx, d, pageSize, fetch, emit) runs a paginated search.
//     It applies the SQL LIMIT or the max_search_results cap, waits on the
//     rate limiter before each extra page, retries each page via the SDK
//     retry config, and stops as soon as Steampipe needs no more rows.
//     fetch returns *apiclient.Page[T] with Total = -1 when the endpoint's
//     count is not a true total (asset search).
//   - ipv4Qual(ctx, d, "ip") reads an INET qual and skips non-IPv4 input.
//   - Transforms: naiveTimeToTimestamp (timezone-less API timestamps, read
//     as UTC), flexBoolValue (apiclient.FlexBool), emptyStringToNil.
//
// Rules for every table: never trigger domain scans or any other side effect
// from a SELECT, never expose or log the API key, and require a qual on every
// list call (the API has no "list all" endpoints).
package criminalip
