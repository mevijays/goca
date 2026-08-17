package gocaclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// APIError is a non-2xx response. goca's handlers render errors as
// {"error": "...", "detail": "..."}, so the message a user sees is the
// server's own wording rather than something invented here - the point of a
// thin client is that the server stays the authority on what went wrong.
type APIError struct {
	Status int
	Msg    string
	Detail string
	// RetryAfter is set from the header on a 429.
	RetryAfter int
}

func (e *APIError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	switch {
	case e.Status == http.StatusUnauthorized:
		// The single most common failure for a client whose token has aged
		// out, and the fix is one command - say so rather than making the
		// user look it up.
		return msg + " (run `gocactl login` to sign in again)"
	case e.Status == http.StatusTooManyRequests && e.RetryAfter > 0:
		return fmt.Sprintf("%s (retry in %ds)", msg, e.RetryAfter)
	}
	return msg
}

func parseAPIError(resp *http.Response, body []byte) error {
	e := &APIError{Status: resp.StatusCode}
	var payload struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error != "" {
		e.Msg, e.Detail = payload.Error, payload.Detail
	} else {
		// Not one of goca's JSON errors - a proxy or a bare 502, most likely.
		// Show a trimmed body so the user has something to go on.
		if s := strings.TrimSpace(string(body)); s != "" {
			e.Msg = truncate(s, 200)
		}
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if n, err := strconv.Atoi(ra); err == nil {
			e.RetryAfter = n
		}
	}
	return e
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// statusIs reports whether err is an APIError with the given status.
func statusIs(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// IsUnauthorized reports a missing, invalid or expired credential.
func IsUnauthorized(err error) bool { return statusIs(err, http.StatusUnauthorized) }

// IsForbidden reports that the caller authenticated but lacks the role.
func IsForbidden(err error) bool { return statusIs(err, http.StatusForbidden) }

// IsNotFound reports that the resource does not exist.
func IsNotFound(err error) bool { return statusIs(err, http.StatusNotFound) }

// IsThrottled reports that the server is rate-limiting this caller.
func IsThrottled(err error) bool { return statusIs(err, http.StatusTooManyRequests) }
