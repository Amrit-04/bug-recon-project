package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
)

// MaxHARSizeBytes caps the maximum size of imported HAR files to 10 MB to prevent memory exhaustion.
const MaxHARSizeBytes = 10 * 1024 * 1024

// HAREntry represents a captured HTTP transaction from a HAR 1.2 archive.
type HAREntry struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	Request         struct {
		Method      string                         `json:"method"`
		URL         string                         `json:"url"`
		Headers     []struct{ Name, Value string } `json:"headers"`
		QueryString []struct{ Name, Value string } `json:"queryString"`
		Cookies     []struct{ Name, Value string } `json:"cookies"`
		PostData    *struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData,omitempty"`
	} `json:"request"`
	Response struct {
		Status  int                            `json:"status"`
		Headers []struct{ Name, Value string } `json:"headers"`
		Content struct {
			Size     int64  `json:"size"`
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"content"`
	} `json:"response"`
}

// HARArchive represents the top-level structure of a HAR file.
type HARArchive struct {
	Log struct {
		Version string     `json:"version"`
		Entries []HAREntry `json:"entries"`
	} `json:"log"`
}

// ImportedHAREntry holds a scope-validated and redacted transaction extracted from a HAR capture.
type ImportedHAREntry struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"` // Query secrets redacted
	Status          int               `json:"status"`
	RequestHeaders  map[string]string `json:"request_headers"`  // Redacted
	ResponseHeaders map[string]string `json:"response_headers"` // Redacted
	QueryParams     map[string]string `json:"query_params,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`  // Sensitive fields masked
	ResponseBody    string            `json:"response_body,omitempty"` // Sensitive fields masked
	Timestamp       time.Time         `json:"timestamp"`
}

// ImportHAR parses a HAR capture, extracts authentication headers/cookies for a specified profile,
// redacts sensitive credentials in the transaction evidence, and filters entries against the scope.
func ImportHAR(data []byte, s *scope.Scope, targetProfile *Profile) ([]*ImportedHAREntry, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty HAR data")
	}
	if len(data) > MaxHARSizeBytes {
		return nil, fmt.Errorf("HAR file size %d bytes exceeds maximum allowed limit of %d bytes", len(data), MaxHARSizeBytes)
	}

	var har HARArchive
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("invalid HAR JSON: %w", err)
	}

	if len(har.Log.Entries) == 0 {
		return nil, fmt.Errorf("HAR log contains no entries")
	}

	var imported []*ImportedHAREntry

	for _, entry := range har.Log.Entries {
		rawURL := strings.TrimSpace(entry.Request.URL)
		if rawURL == "" {
			continue
		}

		// Enforce strict scope checking: discard third-party / out-of-scope entries
		if s != nil && !s.IsURLInScope(rawURL) {
			continue
		}

		reqHeaders := make(map[string]string)
		for _, h := range entry.Request.Headers {
			hName := strings.TrimSpace(h.Name)
			hVal := strings.TrimSpace(h.Value)
			reqHeaders[hName] = hVal

			// If target profile is provided, extract auth tokens into profile (in-memory for active testing only)
			if targetProfile != nil {
				if strings.EqualFold(hName, "Authorization") && hVal != "" {
					targetProfile.SetHeader(hName, hVal)
					if strings.HasPrefix(strings.ToLower(hVal), "bearer ") {
						targetProfile.AuthType = "bearer"
					}
				} else if strings.EqualFold(hName, "X-Api-Key") && hVal != "" {
					targetProfile.SetHeader(hName, hVal)
					targetProfile.AuthType = "api_key"
				}
			}
		}

		// Extract cookies into profile
		if targetProfile != nil {
			for _, c := range entry.Request.Cookies {
				cName := strings.TrimSpace(c.Name)
				cVal := strings.TrimSpace(c.Value)
				if cName != "" && cVal != "" {
					targetProfile.AddCookie(&http.Cookie{
						Name:  cName,
						Value: cVal,
					})
					if targetProfile.AuthType == "" || targetProfile.AuthType == "custom" {
						targetProfile.AuthType = "cookie"
					}
				}
			}
		}

		// Extract query params and redact secrets in parameter values
		queryParams := make(map[string]string)
		for _, q := range entry.Request.QueryString {
			qName := strings.TrimSpace(q.Name)
			qVal := strings.TrimSpace(q.Value)
			if qName != "" {
				if IsSensitiveParam(qName) {
					queryParams[qName] = RedactSecret(qVal)
				} else {
					queryParams[qName] = qVal
				}
			}
		}

		respHeaders := make(map[string]string)
		for _, h := range entry.Response.Headers {
			respHeaders[strings.TrimSpace(h.Name)] = strings.TrimSpace(h.Value)
		}

		reqBody := ""
		if entry.Request.PostData != nil {
			reqBody = string(RedactJSONSecrets([]byte(entry.Request.PostData.Text)))
		}

		respBody := ""
		if entry.Response.Content.Text != "" {
			respBody = string(RedactJSONSecrets([]byte(entry.Response.Content.Text)))
		}

		// Sanitize URL by redacting any secrets in query strings
		safeURL := RedactURLSecrets(rawURL)

		item := &ImportedHAREntry{
			Method:          strings.ToUpper(strings.TrimSpace(entry.Request.Method)),
			URL:             safeURL,
			Status:          entry.Response.Status,
			RequestHeaders:  RedactHeaders(reqHeaders), // Strictly redacted in evidence
			ResponseHeaders: RedactHeaders(respHeaders),
			QueryParams:     queryParams,
			RequestBody:     reqBody,
			ResponseBody:    respBody,
			Timestamp:       entry.StartedDateTime,
		}

		imported = append(imported, item)
	}

	return imported, nil
}
