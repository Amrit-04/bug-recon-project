package validate

import (
	"strings"
)

// RemediationInfo holds concrete remediation guidance and security references.
type RemediationInfo struct {
	CWE         string
	OWASP       string
	Remediation string
	References  []string
}

// remediationDB stores built-in knowledge mappings for scoutr checks.
var remediationDB = map[string]RemediationInfo{
	"hsts": {
		CWE:         "CWE-319: Cleartext Transmission of Sensitive Information",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Enable HTTP Strict Transport Security by setting 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on all HTTPS responses.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		},
	},
	"csp": {
		CWE:         "CWE-1021: Improper Restriction of Rendered UI Layers or Scripts",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Implement a restrictive Content-Security-Policy header (e.g. default-src 'self'; script-src 'self'; object-src 'none') to mitigate XSS and unauthorized framing.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
		},
	},
	"x-frame-options": {
		CWE:         "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors' directive to prevent Clickjacking attacks.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
		},
	},
	"x-content-type-options": {
		CWE:         "CWE-79: Improper Neutralization of Input During Web Page Generation",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing response content away from the declared Content-Type.",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		},
	},
	"cookie-httponly": {
		CWE:         "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Ensure all session and authentication cookies include the 'HttpOnly' attribute to prevent client-side JavaScript access via XSS.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
		},
	},
	"cookie-secure": {
		CWE:         "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Set the 'Secure' attribute on all authentication and sensitive cookies to guarantee transmission only over encrypted TLS channels.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
		},
	},
	"cookie-samesite": {
		CWE:         "CWE-1275: Sensitive Cookie with Improper SameSite Attribute",
		OWASP:       "OWASP A01:2021 - Broken Access Control",
		Remediation: "Configure 'SameSite=Lax' or 'SameSite=Strict' on session cookies to mitigate Cross-Site Request Forgery (CSRF).",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
		},
	},
	"git-exposure": {
		CWE:         "CWE-538: Insertion of Sensitive Information into Externally-Accessible Directory",
		OWASP:       "OWASP A01:2021 - Broken Access Control",
		Remediation: "Block external access to the '.git' directory at the reverse proxy/web server level (e.g. return 404/403 for '/.git/*') and delete repository files from web root.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/538.html",
		},
	},
	"env-exposure": {
		CWE:         "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
		OWASP:       "OWASP A01:2021 - Broken Access Control",
		Remediation: "Move '.env' files outside the public web root immediately, rotate any credentials found in the file, and restrict web server permissions.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},
	"cors-wildcard": {
		CWE:         "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
		OWASP:       "OWASP A05:2021 - Security Misconfiguration",
		Remediation: "Do not dynamically reflect Origin headers when 'Access-Control-Allow-Credentials: true' is present. Use an explicit whitelist of trusted origins.",
		References: []string{
			"https://portswigger.net/web-security/cors",
		},
	},
	"tls-expired": {
		CWE:         "CWE-298: Impairment by Expiration",
		OWASP:       "OWASP A02:2021 - Cryptographic Failures",
		Remediation: "Renew the expired TLS certificate and configure automated renewal monitoring (e.g. ACME / Let's Encrypt / Certbot).",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		},
	},
}

// LookupRemediation finds remediation guidance for a given check, rule, or title keyword.
func LookupRemediation(checkName, ruleID, title string) *RemediationInfo {
	key := strings.ToLower(checkName + " " + ruleID + " " + title)

	switch {
	case strings.Contains(key, ".git") || strings.Contains(key, "git"):
		r := remediationDB["git-exposure"]
		return &r
	case strings.Contains(key, ".env") || strings.Contains(key, "env"):
		r := remediationDB["env-exposure"]
		return &r
	case strings.Contains(key, "hsts") || strings.Contains(key, "strict-transport"):
		r := remediationDB["hsts"]
		return &r
	case strings.Contains(key, "csp") || strings.Contains(key, "content-security"):
		r := remediationDB["csp"]
		return &r
	case strings.Contains(key, "x-frame") || strings.Contains(key, "frame-options") || strings.Contains(key, "clickjack"):
		r := remediationDB["x-frame-options"]
		return &r
	case strings.Contains(key, "nosniff") || strings.Contains(key, "content-type-options"):
		r := remediationDB["x-content-type-options"]
		return &r
	case strings.Contains(key, "httponly"):
		r := remediationDB["cookie-httponly"]
		return &r
	case strings.Contains(key, "cookie") && strings.Contains(key, "secure"):
		r := remediationDB["cookie-secure"]
		return &r
	case strings.Contains(key, "samesite"):
		r := remediationDB["cookie-samesite"]
		return &r
	case strings.Contains(key, "cors"):
		r := remediationDB["cors-wildcard"]
		return &r
	case strings.Contains(key, "tls") || strings.Contains(key, "ssl") || strings.Contains(key, "cert"):
		r := remediationDB["tls-expired"]
		return &r
	}

	return nil
}
