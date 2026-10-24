package validate

import (
	"bytes"
	"regexp"
	"strings"
)

// Common soft-404 HTML indicators
var htmlSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<!DOCTYPE\s+html`),
	regexp.MustCompile(`(?i)<html[^>]*>`),
	regexp.MustCompile(`(?i)<body[^>]*>`),
	regexp.MustCompile(`(?i)<title[^>]*>.*?(404|not\s+found|error|page\s+not\s+found).*?</title>`),
}

// IsHTMLContent returns true if the content appears to be an HTML document.
func IsHTMLContent(body []byte) bool {
	bodyTrimmed := bytes.TrimSpace(body)
	if len(bodyTrimmed) == 0 {
		return false
	}
	for _, sig := range htmlSignatures {
		if sig.Match(bodyTrimmed) {
			return true
		}
	}
	return false
}

// GitHEADSignature: .git/HEAD must strictly match `ref: refs/heads/<branch>` or 40-hex commit hash.
var gitHEADRegex = regexp.MustCompile(`^(?:ref:\s+refs/(?:heads|tags)/[a-zA-Z0-9_\-\./]+|[0-9a-fA-F]{40})\s*$`)

// IsValidGitHEAD validates if the body is a legitimate .git/HEAD response.
func IsValidGitHEAD(body []byte) bool {
	if IsHTMLContent(body) {
		return false
	}
	s := strings.TrimSpace(string(body))
	return gitHEADRegex.MatchString(s)
}

// DotEnvSignature: .env file must contain assignments (e.g., KEY=value) and not HTML.
var envLineRegex = regexp.MustCompile(`(?m)^[A-Za-z0-9_]{2,}\s*=\s*.*$`)

// IsValidDotENV validates if the body appears to be a real .env configuration file.
func IsValidDotENV(body []byte) bool {
	if IsHTMLContent(body) {
		return false
	}
	s := string(body)
	matches := envLineRegex.FindAllString(s, -1)
	return len(matches) >= 1
}

// IsValidDSStore validates if the body starts with Apple .DS_Store magic header.
func IsValidDSStore(body []byte) bool {
	if len(body) < 4 {
		return false
	}
	// Apple .DS_Store starts with \x00\x00\x00\x01
	return body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00 && body[3] == 0x01
}

// Static asset extensions that rarely carry sensitive misconfiguration headers
var staticAssetExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
	".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
}

// IsStaticAssetPath checks if a path points to an image, font, or stylesheet.
func IsStaticAssetPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
