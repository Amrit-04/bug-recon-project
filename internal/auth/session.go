package auth

import (
	"bytes"
	"net/http"
	"strings"
)

// SessionStatus represents the operational status of an authentication session.
type SessionStatus string

const (
	SessionStatusValid   SessionStatus = "valid"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusMissing SessionStatus = "missing"
	SessionStatusUnknown SessionStatus = "unknown"
)

var sessionExpiredPhrases = []string{
	"session expired",
	"token expired",
	"session timed out",
	"session timeout",
	"jwt expired",
	"invalid token",
	"please log in",
	"please sign in",
	"authentication required",
	"unauthorized",
	"login required",
}

var loginPathSubstrings = []string{
	"/login",
	"/signin",
	"/auth",
	"/sso",
	"/oauth/authorize",
}

// DetectSessionStatus inspects an HTTP response and body to determine if the authentication session is valid or expired.
func DetectSessionStatus(resp *http.Response, body []byte) (SessionStatus, string) {
	if resp == nil {
		return SessionStatusUnknown, "no HTTP response available"
	}

	// 1. Direct authentication failure status codes
	if resp.StatusCode == http.StatusUnauthorized {
		return SessionStatusExpired, "HTTP 401 Unauthorized: session or token is invalid or expired"
	}

	// 2. Redirect to login or auth page
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
		loc := resp.Header.Get("Location")
		locLower := strings.ToLower(loc)
		for _, lp := range loginPathSubstrings {
			if strings.Contains(locLower, lp) {
				return SessionStatusExpired, "HTTP redirect to login page: " + loc
			}
		}
	}

	// 3. Inspect body for session expiration messages (especially when apps return 200 with JSON error)
	if len(body) > 0 {
		bodyLower := bytes.ToLower(body)
		for _, phrase := range sessionExpiredPhrases {
			if bytes.Contains(bodyLower, []byte(phrase)) {
				// Only flag if status code is not 200 or body is short error/json
				if resp.StatusCode != http.StatusOK || len(body) < 10000 {
					return SessionStatusExpired, "response body contains session expiration indicator: '" + phrase + "'"
				}
			}
		}
	}

	// 4. Successful responses
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return SessionStatusValid, "HTTP response status indicates active authenticated session"
	}

	return SessionStatusUnknown, "undetermined session status"
}
