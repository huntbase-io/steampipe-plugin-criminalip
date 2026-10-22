package apiclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

// ErrMissingAPIKey is returned by New when no API key is configured.
var ErrMissingAPIKey = errors.New("criminalip: api_key must be set in the connection config or the CRIMINALIP_API_KEY environment variable")

// ErrIPv6NotSupported is returned for IPv6 input; the API only handles IPv4.
var ErrIPv6NotSupported = errors.New("criminalip: only IPv4 addresses are supported")

// APIError is a failure reported by the API, usually as HTTP 200 with a
// non-200 "status" in the body.
type APIError struct {
	Method     string
	Path       string
	HTTPStatus int
	Status     int // the body "status" (or the HTTP status if the body had none)
	Message    string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("criminalip: %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Message)
	switch e.Status {
	case http.StatusForbidden:
		msg += " (the API key is missing or not permitted to call this endpoint)"
	case http.StatusInternalServerError:
		msg += " (Criminal IP also returns this for an invalid API key; check api_key)"
	case 420:
		msg += " (unexpected parameter)"
	}
	return msg
}

// TransportError is a network, Cloudflare, HTML or decoding failure.
type TransportError struct {
	Method     string
	Path       string
	HTTPStatus int
	Err        error
}

func (e *TransportError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("criminalip: %s %s: HTTP %d: %v", e.Method, e.Path, e.HTTPStatus, e.Err)
	}
	return fmt.Sprintf("criminalip: %s %s: %v", e.Method, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// StatusOf returns the API status code of err, or 0 if err is not an *APIError.
func StatusOf(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsNotFound reports whether err means the requested object does not exist
// (status 404, or 420 "No report exists on this scan_id").
func IsNotFound(err error) bool {
	s := StatusOf(err)
	return s == http.StatusNotFound || s == 420
}

// IsBadRequest reports whether err is a 400/412/420 parameter error.
func IsBadRequest(err error) bool {
	s := StatusOf(err)
	return s == http.StatusBadRequest || s == http.StatusPreconditionFailed || s == 420
}

// IsRetryable reports whether a request that failed with err is worth retrying:
// HTTP 429, HTTP 5xx (including HTML 5xx pages), and network timeouts.
//
// A body "status: 500" delivered with HTTP 200 is NOT retried, because the API
// returns exactly that for an invalid API key; retrying would only slow the
// failure down and spend more requests.
func IsRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.HTTPStatus == http.StatusTooManyRequests || apiErr.Status == http.StatusTooManyRequests ||
			apiErr.HTTPStatus >= 500
	}
	var tErr *TransportError
	if errors.As(err, &tErr) {
		if tErr.HTTPStatus == http.StatusTooManyRequests || tErr.HTTPStatus >= 500 {
			return true
		}
		var netErr net.Error
		if errors.As(tErr.Err, &netErr) && netErr.Timeout() {
			return true
		}
		if errors.Is(tErr.Err, context.DeadlineExceeded) {
			return true
		}
	}
	return false
}
