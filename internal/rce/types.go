package rce

import (
	"fmt"
	"strings"
	"time"
)

// RCECategory identifies the specific execution risk category.
type RCECategory string

const (
	CategoryCommandInjection   RCECategory = "command_injection"
	CategorySSTI               RCECategory = "ssti"
	CategoryDeserialization    RCECategory = "unsafe_deserialization"
	CategoryFileProcessing     RCECategory = "file_processing"
	CategoryExpressionLanguage RCECategory = "expression_language"
	CategoryDependency         RCECategory = "dependency_rce"
	CategoryBackgroundJob      RCECategory = "background_job_rce"
)

// RCEConfidence rates the quality and certainty of the candidate discovery signals.
type RCEConfidence string

const (
	ConfidenceLow    RCEConfidence = "low"
	ConfidenceMedium RCEConfidence = "medium"
	ConfidenceHigh   RCEConfidence = "high"
)

// ValidationStatus represents the deterministic lifecycle state of an RCE candidate.
type ValidationStatus string

const (
	StatusDiscovered        ValidationStatus = "discovered"
	StatusCandidate         ValidationStatus = "candidate"
	StatusCorroborated      ValidationStatus = "corroborated"
	StatusNeedsManualReview ValidationStatus = "needs_manual_review"
	StatusValidated         ValidationStatus = "validated"
	StatusRejected          ValidationStatus = "rejected"
	StatusSuppressed        ValidationStatus = "suppressed"
)

// ValidationProfile represents the authorized verification boundary.
type ValidationProfile string

const (
	ProfilePassive    ValidationProfile = "passive"     // Zero target network traffic; metadata/advisory analysis
	ProfileSafeActive ValidationProfile = "safe_active" // Non-destructive marker arithmetic, correlation tokens, negative controls
	ProfileManual     ValidationProfile = "manual"      // Researcher-approved explicit verification plan
)

// AdvisoryProgressionTier captures the 6-stage advisory progression model.
type AdvisoryProgressionTier string

const (
	TierTechDetected           AdvisoryProgressionTier = "tech_detected"
	TierVersionIdentified      AdvisoryProgressionTier = "version_identified"
	TierVersionAffected        AdvisoryProgressionTier = "version_affected"
	TierComponentCorroborated  AdvisoryProgressionTier = "component_corroborated"
	TierComponentReachable     AdvisoryProgressionTier = "component_reachable"
	TierIndependentlyValidated AdvisoryProgressionTier = "independently_validated"
)

// ScoreBreakdown details the transparent, deterministic prioritisation calculation.
type ScoreBreakdown struct {
	BaseRisk        int      `json:"base_risk"`         // 10-35 depending on execution sink severity
	InputExposure   int      `json:"input_exposure"`    // 5-25 (POST body, multipart, URL parameter)
	AuthModifier    int      `json:"auth_modifier"`     // 0-20 (Anonymous > Authenticated Member > Admin)
	TechCVEModifier int      `json:"tech_cve_modifier"` // 0-25 (Corroborated reachable CVE > tech detected)
	ChainModifier   int      `json:"chain_modifier"`    // 0-15 (Part of multi-step processing chain)
	TotalScore      int      `json:"total_score"`       // Clamped 0-100
	Explanations    []string `json:"explanations"`      // Human-readable scoring rationale
}

// ProcessingStep represents a node in a multi-step processing chain.
type ProcessingStep struct {
	EndpointID string `json:"endpoint_id"`
	Route      string `json:"route"`
	Method     string `json:"method"`
	Role       string `json:"role"`      // e.g. "upload_source", "converter_sink", "worker_trigger"
	DataFlow   string `json:"data_flow"` // e.g. "supplies file reference for document conversion"
}

// ProcessingChain models connected workflows (e.g. Upload -> Preview/Conversion -> Worker Execution).
type ProcessingChain struct {
	ChainID     string           `json:"chain_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Steps       []ProcessingStep `json:"steps"`
}

// Advisory represents a public vulnerability advisory (CVE, GHSA, NVD).
type Advisory struct {
	ID                    string   `json:"id"`                     // e.g. "CVE-2022-22965", "CVE-2021-44228"
	Title                 string   `json:"title"`                  // e.g. "Spring Framework RCE (Spring4Shell)"
	AffectedProduct       string   `json:"affected_product"`       // e.g. "spring-framework", "log4j-core"
	VulnerableRange       string   `json:"vulnerable_range"`       // e.g. ">= 5.3.0, < 5.3.18"
	FixedVersions         []string `json:"fixed_versions"`         // e.g. ["5.3.18", "5.2.20"]
	VulnType              string   `json:"vuln_type"`              // e.g. "DataBinder ClassLoader RCE"
	Prerequisites         string   `json:"prerequisites"`          // e.g. "Running on JDK9+, packaged as WAR"
	ReachabilityCondition string   `json:"reachability_condition"` // Functional feature required for reachability
	References            []string `json:"references"`
	Severity              string   `json:"severity"` // "Critical", "High", "Medium"
}

// AdvisoryMatch links an advisory to an observed endpoint with a progression tier.
type AdvisoryMatch struct {
	Advisory           Advisory                `json:"advisory"`
	DetectedVersion    string                  `json:"detected_version"`
	ProgressionTier    AdvisoryProgressionTier `json:"progression_tier"`
	ReachabilityReason string                  `json:"reachability_reason"`
	MatchedEndpointIDs []string                `json:"matched_endpoint_ids"`
}

// ValidationAttempt stores structured evidence of a validation check.
type ValidationAttempt struct {
	AttemptID                string            `json:"attempt_id"`
	Profile                  ValidationProfile `json:"profile"`
	Timestamp                time.Time         `json:"timestamp"`
	Parameter                string            `json:"parameter"`
	CorrelationID            string            `json:"correlation_id"`
	ControlRequestSent       string            `json:"control_request_sent,omitempty"`
	ControlResponseObserved  string            `json:"control_response_observed,omitempty"`
	PositiveRequestSent      string            `json:"positive_request_sent,omitempty"`
	PositiveResponseObserved string            `json:"positive_response_observed,omitempty"`
	MarkerExpected           string            `json:"marker_expected,omitempty"`
	MarkerFound              bool              `json:"marker_found"`
	ReflectionExcluded       bool              `json:"reflection_excluded"`
	ExecutionConfirmed       bool              `json:"execution_confirmed"`
	Notes                    string            `json:"notes,omitempty"`
}

// RCECandidate is the core data model for an RCE attack surface candidate or verified finding.
type RCECandidate struct {
	ID                 string              `json:"id"`
	Target             string              `json:"target"`
	Origin             string              `json:"origin"`
	Route              string              `json:"route"`
	HTTPMethod         string              `json:"http_method"`
	Category           RCECategory         `json:"category"`
	FeatureType        string              `json:"feature_type"`
	Hypothesis         string              `json:"hypothesis"`
	SuspectedSink      string              `json:"suspected_sink"`
	RelevantParams     []string            `json:"relevant_params,omitempty"`
	RelevantBodyFields []string            `json:"relevant_body_fields,omitempty"`
	RelevantTech       []string            `json:"relevant_tech,omitempty"`
	DiscoverySource    string              `json:"discovery_source"`
	EvidenceSignals    []string            `json:"evidence_signals"`
	Confidence         RCEConfidence       `json:"confidence"`
	PriorityScore      int                 `json:"priority_score"`
	ScoreBreakdown     ScoreBreakdown      `json:"score_breakdown"`
	AssociatedChains   []ProcessingChain   `json:"associated_chains,omitempty"`
	MatchingAdvisories []AdvisoryMatch     `json:"matching_advisories,omitempty"`
	ValidationAttempts []ValidationAttempt `json:"validation_attempts,omitempty"`
	LastAttempt        *ValidationAttempt  `json:"last_attempt,omitempty"`
	ValidationStatus   ValidationStatus    `json:"validation_status"`
	ResearcherNotes    string              `json:"researcher_notes,omitempty"`
	DiscoveredAt       time.Time           `json:"discovered_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

// Key returns a unique deduplication string for this candidate.
func (c *RCECandidate) Key() string {
	return fmt.Sprintf("%s:%s:%s:%s", strings.ToUpper(c.HTTPMethod), strings.ToLower(c.Origin), c.Route, c.Category)
}

// RCEOverview provides aggregate dashboard statistics.
type RCEOverview struct {
	TotalCandidates      int                 `json:"total_candidates"`
	HighPriorityCount    int                 `json:"high_priority_count"`
	AdvisoryMatchCount   int                 `json:"advisory_match_count"`
	AwaitingValidation   int                 `json:"awaiting_validation"`
	CorroboratedCount    int                 `json:"corroborated_count"`
	ValidatedCount       int                 `json:"validated_count"`
	CategoryDistribution map[RCECategory]int `json:"category_distribution"`
	RecentActivity       []string            `json:"recent_activity"`
}
