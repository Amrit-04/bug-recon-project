package auth

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	sensitiveHeaderRegex = regexp.MustCompile(`(?i)^(authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|session|token|apikey|secret)$`)
	sensitiveParamRegex  = regexp.MustCompile(`(?i)^(token|password|passwd|secret|auth|bearer|jwt|key|signature|sig|credential|cookie|session|csrf|xsrf|api_key|apikey|access_token|refresh_token|private)$`)
)

// IsSensitiveHeader returns true if the header name typically contains authentication credentials or session tokens.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaderRegex.MatchString(strings.TrimSpace(name))
}

// IsSensitiveParam returns true if the parameter name matches credential or authentication secrets.
func IsSensitiveParam(name string) bool {
	return sensitiveParamRegex.MatchString(strings.TrimSpace(name))
}

// RedactSecret replaces raw secret strings with a deterministic redacted representation.
// Short secrets become "[REDACTED]". Longer secrets preserve a safe 4-char prefix and sha256 fingerprint.
func RedactSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return "[REDACTED]"
	}

	prefix := secret[:4]
	hash := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%s...[REDACTED:%x]", prefix, hash[:4])
}

// RedactHeaders returns a copy of the headers with sensitive values redacted.
func RedactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if IsSensitiveHeader(k) {
			out[k] = RedactSecret(v)
		} else {
			out[k] = v
		}
	}
	return out
}

// RedactHTTPHeaders returns a copy of http.Header with sensitive values redacted.
func RedactHTTPHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	out := make(http.Header, len(headers))
	for k, vals := range headers {
		if IsSensitiveHeader(k) {
			redactedVals := make([]string, len(vals))
			for i, v := range vals {
				redactedVals[i] = RedactSecret(v)
			}
			out[k] = redactedVals
		} else {
			out[k] = append([]string(nil), vals...)
		}
	}
	return out
}

// RedactCookies returns a copy of cookies with values redacted.
func RedactCookies(cookies []*http.Cookie) []*http.Cookie {
	if cookies == nil {
		return nil
	}
	out := make([]*http.Cookie, len(cookies))
	for i, c := range cookies {
		clone := *c
		clone.Value = RedactSecret(c.Value)
		out[i] = &clone
	}
	return out
}

// RedactURLSecrets inspects query parameter values in rawURL and redacts any that contain tokens, secrets, or keys.
func RedactURLSecrets(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	q := u.Query()
	modified := false
	for k, vals := range q {
		if IsSensitiveParam(k) {
			redactedVals := make([]string, len(vals))
			for i, v := range vals {
				redactedVals[i] = RedactSecret(v)
			}
			q[k] = redactedVals
			modified = true
		}
	}

	if modified {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// RedactJSONSecrets masks sensitive keys inside a JSON object without destroying structure.
func RedactJSONSecrets(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err == nil {
		maskSensitiveMap(m)
		out, err := json.Marshal(m)
		if err == nil {
			return out
		}
	}
	return data
}

func maskSensitiveMap(m map[string]any) {
	for k, v := range m {
		if IsSensitiveParam(k) || IsSensitiveHeader(k) {
			if strVal, ok := v.(string); ok {
				m[k] = RedactSecret(strVal)
			} else {
				m[k] = "[REDACTED]"
			}
		} else if subMap, ok := v.(map[string]any); ok {
			maskSensitiveMap(subMap)
		}
	}
}
