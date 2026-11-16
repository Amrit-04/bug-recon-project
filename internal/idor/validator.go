package idor

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
)

// IDORStatus represents the deterministic classification of a differential testing result.
type IDORStatus string

const (
	IDORStatusCandidate              IDORStatus = "Candidate"
	IDORStatusNeedsReview            IDORStatus = "NeedsReview"
	IDORStatusAuthorizedShare        IDORStatus = "AuthorizedShare"
	IDORStatusSameUser               IDORStatus = "SameUser"
	IDORStatusSameTenantUnauthorized IDORStatus = "SameTenantUnauthorized"
	IDORStatusUnauthorizedRole       IDORStatus = "UnauthorizedRole"
	IDORStatusCrossTenant            IDORStatus = "CrossTenant"
	IDORStatusCrossInstance          IDORStatus = "CrossInstance"
	IDORStatusCacheDeception         IDORStatus = "CacheDeception"
	IDORStatusCorroborated           IDORStatus = "Corroborated"
	IDORStatusConfirmed              IDORStatus = "Confirmed"
)

// ValidateComparison performs strict deterministic validation on a differential comparison result.
// A 200 OK is NOT sufficient evidence of IDOR. It requires confirmed owner baseline, non-public validation,
// and demonstrable unauthorized data disclosure to another principal.
func ValidateComparison(comp *ComparisonResult) (IDORStatus, *findings.Finding, error) {
	if comp == nil {
		return IDORStatusCandidate, nil, fmt.Errorf("comparison result is nil")
	}

	// Same-user testing is invalid
	if comp.Status == IDORStatusSameUser {
		return IDORStatusSameUser, nil, nil
	}

	// Unknown access policy requires manual review
	if comp.Candidate.AccessPolicy == AccessPolicyUnknown || comp.Candidate.AccessPolicy == "unknown" {
		return IDORStatusNeedsReview, nil, nil
	}

	if comp.Status == IDORStatusNeedsReview {
		return IDORStatusNeedsReview, nil, nil
	}

	// Gate 1: Baseline owner access required
	if comp.OwnerStatus != 200 {
		return IDORStatusCandidate, nil, nil
	}

	// Gate 2: Public resources are excluded
	if comp.IsPublicResource {
		return IDORStatusNeedsReview, nil, nil
	}

	// Gate 3: Access denied is correctly protected
	if comp.TesterStatus == 401 || comp.TesterStatus == 403 || comp.TesterStatus == 404 {
		return IDORStatusCandidate, nil, nil
	}

	// Gate 4: Authorized share / Expected access permitted
	if comp.IsAuthorizedShare {
		return IDORStatusAuthorizedShare, nil, nil
	}

	// Gate 5: Web Cache Deception detection (verified with cross-account replay evidence)
	if comp.IsCacheDeception && comp.CacheReplayVerified {
		findingID := fmt.Sprintf("cache-leak-%x", sha256.Sum256([]byte(comp.ID)))[:12]
		finding := &findings.Finding{
			ID:         findingID,
			CheckName:  "web-cache-deception",
			RuleID:     "CACHE-DECEPT-001",
			Target:     comp.RequestURL,
			Path:       comp.Candidate.RouteTemplate,
			Title:      fmt.Sprintf("Web Cache Deception / Private Response Leakage on %s", comp.Candidate.RouteTemplate),
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceHigh,
			Evidence: fmt.Sprintf("Tester received cached response of owner's private object '%s'. Cache-Control: '%s', Age: '%s'. %s",
				comp.Candidate.ObjectID, comp.CacheHeaders["Cache-Control"], comp.CacheHeaders["Age"], comp.EvidenceNotes),
			Request:     fmt.Sprintf("GET %s HTTP/1.1\nHost: [target]\nAuthorization: [REDACTED:tester_token]\n", comp.RequestURL),
			Response:    fmt.Sprintf("HTTP/1.1 200 OK\nCache-Control: %s\nAge: %s\n\n%s", comp.CacheHeaders["Cache-Control"], comp.CacheHeaders["Age"], comp.RedactedTesterResponse),
			Impact:      "A private response belonging to one account was retained by an intermediary or public web cache and served to a distinct user account, leaking confidential object data.",
			Remediation: "Ensure sensitive endpoints set 'Cache-Control: no-store, private' and do not permit unauthenticated or cross-session caching.",
			References: []string{
				"https://cwe.mitre.org/data/definitions/524.html",
				"https://owasp.org/www-community/attacks/Web_Cache_Deception",
			},
			Timestamp: time.Now(),
		}
		return IDORStatusCacheDeception, finding, nil
	}

	// Gate 6: Verify concrete unauthorized data disclosure
	if !comp.IsDisclosed {
		if comp.TesterStatus == 200 {
			return IDORStatusNeedsReview, nil, nil
		}
		return IDORStatusCandidate, nil, nil
	}

	// Gate 7: Verified unauthorized disclosure across boundaries
	var status IDORStatus
	var severity findings.Severity
	var ruleID string
	var title string
	var impact string

	switch {
	case comp.Status == IDORStatusUnauthorizedRole:
		status = IDORStatusUnauthorizedRole
		severity = findings.SeverityHigh
		ruleID = "IDOR-ROLE-001"
		title = fmt.Sprintf("Intra-Tenant Unauthorized Role Access (Privilege Escalation) on %s", comp.Candidate.RouteTemplate)
		impact = fmt.Sprintf("User '%s' (role '%s') accessed role-restricted object '%s' owned by '%s' (role '%s') in violation of role policy. Allowed roles: %v.",
			comp.TesterProfile.PrincipalLabel, comp.TesterProfile.RoleLabel, comp.Candidate.ObjectID,
			comp.OwnerProfile.PrincipalLabel, comp.Candidate.OwnerRole, comp.Candidate.AllowedRoles)

	case comp.Boundary == BoundaryCrossInstance:
		status = IDORStatusCrossInstance
		// Calibrate severity based on demonstrated impact
		if len(comp.DisclosedSensitiveFields) > 0 {
			severity = findings.SeverityCritical
		} else {
			severity = findings.SeverityHigh
		}
		ruleID = "IDOR-INSTANCE-001"
		title = fmt.Sprintf("Cross-Instance Insecure Direct Object Reference (IDOR) on %s", comp.Candidate.RouteTemplate)
		impact = fmt.Sprintf("User '%s' (instance '%s') was able to access private object '%s' hosted in separate deployment instance '%s'. Disclosed sensitive fields: %v.",
			comp.TesterProfile.PrincipalLabel, comp.TesterProfile.InstanceLabel, comp.Candidate.ObjectID, comp.Candidate.OwnerInstance, comp.DisclosedSensitiveFields)

	case comp.Boundary == BoundaryCrossTenant:
		status = IDORStatusCrossTenant
		if len(comp.DisclosedSensitiveFields) > 0 {
			severity = findings.SeverityHigh
		} else {
			severity = findings.SeverityMedium
		}
		ruleID = "IDOR-TENANT-001"
		title = fmt.Sprintf("Cross-Tenant Insecure Direct Object Reference (IDOR) on %s", comp.Candidate.RouteTemplate)
		impact = fmt.Sprintf("User '%s' (tenant '%s') was able to access private object '%s' belonging to tenant '%s'. Complete multi-tenant isolation failure.",
			comp.TesterProfile.PrincipalLabel, comp.TesterProfile.TenantLabel, comp.Candidate.ObjectID, comp.Candidate.OwnerTenant)

	case comp.Boundary == BoundarySameTenant:
		// Intra-tenant authorization check
		status = IDORStatusSameTenantUnauthorized
		severity = findings.SeverityMedium
		ruleID = "IDOR-INTRA-001"
		title = fmt.Sprintf("Intra-Tenant Insecure Direct Object Reference (IDOR) on %s", comp.Candidate.RouteTemplate)
		impact = fmt.Sprintf("User '%s' accessed private object '%s' owned by '%s' within same tenant '%s' in violation of access policy '%s'.",
			comp.TesterProfile.PrincipalLabel, comp.Candidate.ObjectID, comp.OwnerProfile.PrincipalLabel, comp.Candidate.OwnerTenant, comp.Candidate.AccessPolicy)
	}

	findingID := fmt.Sprintf("idor-%x", sha256.Sum256([]byte(comp.ID)))[:12]

	finding := &findings.Finding{
		ID:         findingID,
		CheckName:  "idor-differential-authorization",
		RuleID:     ruleID,
		Target:     comp.RequestURL,
		Path:       comp.Candidate.RouteTemplate,
		Title:      title,
		Severity:   severity,
		Confidence: findings.ConfidenceHigh,
		Evidence: fmt.Sprintf("Owner '%s' (instance: '%s', tenant: '%s', role: '%s') established 200 OK baseline. Tester '%s' (instance: '%s', tenant: '%s', role: '%s') accessed private object '%s'. Disclosed fields: %v. Similarity: %.2f. Anon HTTP: %d.",
			comp.OwnerProfile.PrincipalLabel, comp.OwnerProfile.InstanceLabel, comp.OwnerProfile.TenantLabel, comp.OwnerProfile.RoleLabel,
			comp.TesterProfile.PrincipalLabel, comp.TesterProfile.InstanceLabel, comp.TesterProfile.TenantLabel, comp.TesterProfile.RoleLabel,
			comp.Candidate.ObjectID, comp.DisclosedSensitiveFields, comp.BodySimilarity, comp.AnonStatus),
		Request: fmt.Sprintf("GET %s HTTP/1.1\nHost: [target]\nAuthorization: [REDACTED:tester_token]\n", comp.RequestURL),
		Response: fmt.Sprintf("HTTP/1.1 %d OK\nContent-Type: %s\n\n%s",
			comp.TesterStatus, comp.TesterContentType, comp.RedactedTesterResponse),
		Impact:      impact,
		Remediation: "Implement robust server-side access control checks verifying that the authenticated user possesses explicit authorization to access the requested resource identifier.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/639.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
		Timestamp: time.Now(),
	}

	return status, finding, nil
}

// GenerateIDORReportMarkdown formats comparison findings into a human-readable markdown report.
func GenerateIDORReportMarkdown(comparisons []*ComparisonResult, findingsList []*findings.Finding) string {
	var b strings.Builder

	b.WriteString("# Scoutr IDOR Research & Validation Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Total Comparisons:** %d\n", len(comparisons)))
	b.WriteString(fmt.Sprintf("**Confirmed / Corroborated Vulnerabilities:** %d\n\n", len(findingsList)))

	b.WriteString("## Executive Summary\n\n")
	if len(findingsList) == 0 {
		b.WriteString("No confirmed Insecure Direct Object Reference vulnerabilities were identified during differential authorization testing.\n\n")
	} else {
		b.WriteString(fmt.Sprintf("Differential testing identified **%d** instances of unauthorized cross-account object access.\n\n", len(findingsList)))
	}

	b.WriteString("## Detailed Findings\n\n")
	for i, f := range findingsList {
		b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
		b.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", f.Severity))
		b.WriteString(fmt.Sprintf("- **Target URL:** `%s`\n", f.Target))
		b.WriteString(fmt.Sprintf("- **Route:** `%s`\n", f.Path))
		b.WriteString(fmt.Sprintf("- **Impact:** %s\n", f.Impact))
		b.WriteString(fmt.Sprintf("- **Evidence:** %s\n\n", f.Evidence))
		b.WriteString("```http\n")
		b.WriteString(f.Response)
		b.WriteString("\n```\n\n")
		b.WriteString(fmt.Sprintf("- **Remediation:** %s\n\n", f.Remediation))
	}

	b.WriteString("## Comparison Matrix\n\n")
	b.WriteString("| Route | Object ID | Boundary | Policy | Owner | Tester | Anon | Result | Notes |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range comparisons {
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %d | %d | %d | **%s** | %s |\n",
			c.Candidate.RouteTemplate, c.Candidate.ObjectID, c.Boundary, c.Candidate.AccessPolicy, c.OwnerStatus, c.TesterStatus, c.AnonStatus, c.Status, c.EvidenceNotes))
	}
	b.WriteString("\n")

	return b.String()
}
