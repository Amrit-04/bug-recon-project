package rce

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// AdvisoryRegistry manages known RCE advisories and coordinates reachability checks.
type AdvisoryRegistry struct {
	advisories []Advisory
	mu         sync.RWMutex
}

// NewAdvisoryRegistry initializes the registry with curated public CVE intelligence.
func NewAdvisoryRegistry() *AdvisoryRegistry {
	r := &AdvisoryRegistry{}
	r.loadDefaultAdvisories()
	return r
}

func (r *AdvisoryRegistry) loadDefaultAdvisories() {
	r.advisories = []Advisory{
		{
			ID:                    "CVE-2022-22965",
			Title:                 "Spring Framework RCE via DataBinder (Spring4Shell)",
			AffectedProduct:       "spring-framework",
			VulnerableRange:       ">= 5.3.0, < 5.3.18; >= 5.2.0, < 5.2.20",
			FixedVersions:         []string{"5.3.18", "5.2.20"},
			VulnType:              "DataBinder ClassLoader Access to Tomcat AccessLogValve",
			Prerequisites:         "Running on JDK 9+ packaged as traditional WAR deployed on Tomcat",
			ReachabilityCondition: "Endpoint must bind request parameters to Java POJO objects (e.g. POST form/JSON body fields)",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22965", "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2021-44228",
			Title:                 "Apache Log4j2 JNDI Injection RCE (Log4Shell)",
			AffectedProduct:       "log4j-core",
			VulnerableRange:       ">= 2.0.0, < 2.15.0",
			FixedVersions:         []string{"2.15.0", "2.16.0", "2.17.0"},
			VulnType:              "Unsafe JNDI Lookup in Log Message Formatting",
			Prerequisites:         "Target application logs user-controllable input (User-Agent, headers, query parameters) via Log4j2",
			ReachabilityCondition: "Logging sink receives external input headers or query parameters",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2023-46604",
			Title:                 "Apache ActiveMQ OpenWire Deserialization RCE",
			AffectedProduct:       "activemq",
			VulnerableRange:       "< 5.15.16; >= 5.16.0, < 5.16.7; >= 5.17.0, < 5.17.6; >= 5.18.0, < 5.18.3",
			FixedVersions:         []string{"5.15.16", "5.16.7", "5.17.6", "5.18.3"},
			VulnType:              "Class PathXmlApplicationContext Instantiation in OpenWire Protocol",
			Prerequisites:         "ActiveMQ broker service or web console exposed",
			ReachabilityCondition: "ActiveMQ endpoint or message queue interface reachable",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-46604"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2022-26134",
			Title:                 "Atlassian Confluence Server OGNL Injection RCE",
			AffectedProduct:       "confluence",
			VulnerableRange:       "< 7.4.17; >= 7.13.0, < 7.13.7; >= 7.14.0, < 7.14.3; >= 7.15.0, < 7.15.2; >= 7.16.0, < 7.16.4; >= 7.17.0, < 7.17.4; >= 7.18.0, < 7.18.1",
			FixedVersions:         []string{"7.4.17", "7.13.7", "7.14.3", "7.15.2", "7.16.4", "7.17.4", "7.18.1"},
			VulnType:              "OGNL Evaluation in HTTP Request URI Header",
			Prerequisites:         "Unauthenticated access to Confluence web server",
			ReachabilityCondition: "Web URI handler evaluates OGNL expressions",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-26134"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2021-22205",
			Title:                 "GitLab CE/EE ExifTool Command Injection via Image Upload",
			AffectedProduct:       "gitlab",
			VulnerableRange:       ">= 11.9.0, < 13.8.8; >= 13.9.0, < 13.9.6; >= 13.10.0, < 13.10.3",
			FixedVersions:         []string{"13.8.8", "13.9.6", "13.10.3"},
			VulnType:              "ExifTool Improper Sanitization of DjVu Annotations",
			Prerequisites:         "File upload functionality processing images or DjVu files",
			ReachabilityCondition: "Endpoint must accept image/avatar or document uploads",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-22205"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2024-4577",
			Title:                 "PHP CGI Argument Injection RCE",
			AffectedProduct:       "php",
			VulnerableRange:       ">= 8.1.0, < 8.1.29; >= 8.2.0, < 8.2.20; >= 8.3.0, < 8.3.8",
			FixedVersions:         []string{"8.1.29", "8.2.20", "8.3.8"},
			VulnType:              "Best-Fit Character Encoding Bypass to CLI Argument Injection",
			Prerequisites:         "PHP running on Windows or under CGI mode (Apache mod_cgi, FastCGI)",
			ReachabilityCondition: "PHP script invocation with query string parameters",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4577"},
			Severity:              "Critical",
		},
		{
			ID:                    "CVE-2017-5638",
			Title:                 "Apache Struts2 Content-Type OGNL RCE",
			AffectedProduct:       "struts",
			VulnerableRange:       ">= 2.3.5, <= 2.3.31; >= 2.5.0, <= 2.5.10",
			FixedVersions:         []string{"2.3.32", "2.5.10.1"},
			VulnType:              "Jakarta Multipart Request Parser OGNL Evaluation",
			Prerequisites:         "Struts2 application parsing multipart/form-data requests",
			ReachabilityCondition: "Endpoint handles file upload or multipart forms",
			References:            []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"},
			Severity:              "Critical",
		},
	}
}

// GetAllAdvisories returns all registered advisories.
func (r *AdvisoryRegistry) GetAllAdvisories() []Advisory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Advisory, len(r.advisories))
	copy(out, r.advisories)
	return out
}

// CorrelateCandidate evaluates tech fingerprints on a candidate against known advisories,
// advancing through the 6-tier progression model.
func (r *AdvisoryRegistry) CorrelateCandidate(cand *RCECandidate) []AdvisoryMatch {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []AdvisoryMatch

	for _, adv := range r.advisories {
		match := r.evaluateAdvisoryForCandidate(adv, cand)
		if match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

func (r *AdvisoryRegistry) evaluateAdvisoryForCandidate(adv Advisory, cand *RCECandidate) *AdvisoryMatch {
	productLower := strings.ToLower(adv.AffectedProduct)
	var detectedVersion string
	techDetected := false

	// Step 1: Detect matching technology
	for _, tech := range cand.RelevantTech {
		tLower := strings.ToLower(tech)
		if strings.Contains(tLower, productLower) || matchesProductAlias(productLower, tLower) {
			techDetected = true
			detectedVersion = extractVersion(tech)
			break
		}
	}

	if !techDetected {
		return nil
	}

	// Tier 1: Technology detected
	tier := TierTechDetected
	reachabilityReason := fmt.Sprintf("Technology '%s' detected in endpoint fingerprints.", adv.AffectedProduct)

	// Step 2 & 3: Version identified & check if affected
	if detectedVersion != "" {
		if !MatchesRange(detectedVersion, adv.VulnerableRange) {
			return nil // Version was identified and is not affected by this advisory
		}

		tier = TierVersionAffected
		reachabilityReason = fmt.Sprintf("Identified version '%s' falls within vulnerable range '%s'.",
			detectedVersion, adv.VulnerableRange)

		// Step 4: Component corroborated
		// Check if candidate functional category matches vulnerability sink
		if isComponentCorroborated(adv, cand) {
			tier = TierComponentCorroborated
			reachabilityReason = fmt.Sprintf("Vulnerable component corroborated by endpoint functionality (%s).",
				cand.FeatureType)

			// Step 5: Component reachable
			if isComponentReachable(adv, cand) {
				tier = TierComponentReachable
				reachabilityReason = fmt.Sprintf("Component reachable: endpoint '%s %s' exposes required inputs (%s).",
					cand.HTTPMethod, cand.Route, adv.ReachabilityCondition)
			}
		}
	}

	return &AdvisoryMatch{
		Advisory:           adv,
		DetectedVersion:    detectedVersion,
		ProgressionTier:    tier,
		ReachabilityReason: reachabilityReason,
		MatchedEndpointIDs: []string{cand.ID},
	}
}

func matchesProductAlias(product, tech string) bool {
	switch product {
	case "spring-framework":
		return strings.Contains(tech, "spring") || strings.Contains(tech, "java")
	case "log4j-core":
		return strings.Contains(tech, "log4j")
	case "confluence":
		return strings.Contains(tech, "confluence") || strings.Contains(tech, "atlassian")
	case "gitlab":
		return strings.Contains(tech, "gitlab")
	case "activemq":
		return strings.Contains(tech, "activemq")
	case "php":
		return strings.Contains(tech, "php")
	case "struts":
		return strings.Contains(tech, "struts")
	}
	return false
}

func isComponentCorroborated(adv Advisory, cand *RCECandidate) bool {
	switch adv.ID {
	case "CVE-2022-22965": // Spring4Shell
		return cand.Category == CategoryCommandInjection || cand.Category == CategoryFileProcessing ||
			cand.HTTPMethod == "POST" || len(cand.RelevantBodyFields) > 0
	case "CVE-2021-44228": // Log4j
		return len(cand.RelevantParams) > 0 || len(cand.RelevantBodyFields) > 0
	case "CVE-2023-46604": // ActiveMQ
		return cand.Category == CategoryDeserialization || cand.Category == CategoryBackgroundJob
	case "CVE-2022-26134": // Confluence OGNL
		return cand.Category == CategorySSTI || cand.Category == CategoryExpressionLanguage ||
			strings.Contains(strings.ToLower(cand.Route), "confluence")
	case "CVE-2021-22205": // GitLab ExifTool
		return cand.Category == CategoryFileProcessing || strings.Contains(strings.ToLower(cand.Route), "upload")
	case "CVE-2024-4577": // PHP CGI
		return cand.Category == CategoryCommandInjection || len(cand.RelevantParams) > 0
	case "CVE-2017-5638": // Struts2 OGNL
		return cand.Category == CategoryFileProcessing || cand.Category == CategoryExpressionLanguage ||
			cand.HTTPMethod == "POST"
	}
	return false
}

func isComponentReachable(adv Advisory, cand *RCECandidate) bool {
	switch adv.ID {
	case "CVE-2022-22965":
		// Reachable if POST with body fields
		return cand.HTTPMethod == "POST" && (len(cand.RelevantBodyFields) > 0 || len(cand.RelevantParams) > 0)
	case "CVE-2021-44228":
		// Reachable if receives external input
		return len(cand.RelevantParams) > 0 || len(cand.RelevantBodyFields) > 0
	case "CVE-2023-46604":
		return cand.Category == CategoryDeserialization || cand.Category == CategoryBackgroundJob
	case "CVE-2022-26134":
		return cand.Route != ""
	case "CVE-2021-22205":
		return cand.Category == CategoryFileProcessing && (cand.HTTPMethod == "POST" || cand.HTTPMethod == "PUT")
	case "CVE-2024-4577":
		return len(cand.RelevantParams) > 0
	case "CVE-2017-5638":
		return cand.HTTPMethod == "POST" && (cand.Category == CategoryFileProcessing || len(cand.RelevantBodyFields) > 0)
	}
	return false
}

var versionExtractorRegex = regexp.MustCompile(`(?i)(?:v|version|\/|-|\s)([0-9]+(?:\.[0-9]+)+(?:-[a-z0-9]+)?)`)

func extractVersion(tech string) string {
	m := versionExtractorRegex.FindStringSubmatch(tech)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// SemVer represents parsed major, minor, patch, and build values.
type SemVer struct {
	Parts []int
}

// ParseSemVer parses version numbers such as "5.3.17", "2.14", "1.2.3.4".
func ParseSemVer(v string) (*SemVer, error) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Strip build metadata or prerelease after hyphen or plus
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}

	segments := strings.Split(v, ".")
	var parts []int
	for _, s := range segments {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		num, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid version component '%s': %w", s, err)
		}
		parts = append(parts, num)
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("empty version string")
	}

	return &SemVer{Parts: parts}, nil
}

// Compare compares two versions: -1 if a < b, 0 if a == b, 1 if a > b.
func (a *SemVer) Compare(b *SemVer) int {
	maxLen := len(a.Parts)
	if len(b.Parts) > maxLen {
		maxLen = len(b.Parts)
	}

	for i := 0; i < maxLen; i++ {
		valA := 0
		if i < len(a.Parts) {
			valA = a.Parts[i]
		}
		valB := 0
		if i < len(b.Parts) {
			valB = b.Parts[i]
		}

		if valA < valB {
			return -1
		}
		if valA > valB {
			return 1
		}
	}
	return 0
}

// MatchesRange evaluates whether a version string satisfies a range expression.
// Supports multi-range disjunctions separated by ';' (e.g. ">= 5.3.0, < 5.3.18; >= 5.2.0, < 5.2.20").
func MatchesRange(versionStr, rangeExpr string) bool {
	v, err := ParseSemVer(versionStr)
	if err != nil {
		return false
	}

	// Split by semicolon for OR conditions
	disjunctions := strings.Split(rangeExpr, ";")
	for _, disj := range disjunctions {
		disj = strings.TrimSpace(disj)
		if disj == "" {
			continue
		}

		if matchesConjuncts(v, disj) {
			return true
		}
	}

	return false
}

func matchesConjuncts(v *SemVer, conjunctsExpr string) bool {
	// Split by comma for AND conditions (e.g. ">= 5.3.0, < 5.3.18")
	parts := strings.Split(conjunctsExpr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if !matchesSingleConstraint(v, p) {
			return false
		}
	}
	return true
}

func matchesSingleConstraint(v *SemVer, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	var op string
	var targetVerStr string

	if strings.HasPrefix(constraint, "<=") {
		op = "<="
		targetVerStr = strings.TrimSpace(constraint[2:])
	} else if strings.HasPrefix(constraint, ">=") {
		op = ">="
		targetVerStr = strings.TrimSpace(constraint[2:])
	} else if strings.HasPrefix(constraint, "<") {
		op = "<"
		targetVerStr = strings.TrimSpace(constraint[1:])
	} else if strings.HasPrefix(constraint, ">") {
		op = ">"
		targetVerStr = strings.TrimSpace(constraint[1:])
	} else if strings.HasPrefix(constraint, "=") {
		op = "="
		targetVerStr = strings.TrimSpace(constraint[1:])
	} else {
		op = "="
		targetVerStr = constraint
	}

	targetVer, err := ParseSemVer(targetVerStr)
	if err != nil {
		return false
	}

	cmp := v.Compare(targetVer)
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	}
	return false
}
