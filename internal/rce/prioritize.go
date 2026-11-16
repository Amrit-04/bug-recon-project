package rce

import (
	"fmt"
	"sort"
	"strings"
)

// Prioritizer computes deterministic research priority scores and transparent score breakdowns.
type Prioritizer struct{}

// NewPrioritizer creates a new Prioritizer instance.
func NewPrioritizer() *Prioritizer {
	return &Prioritizer{}
}

// PrioritizeCandidates scores all candidates and sorts them descending by PriorityScore.
func (p *Prioritizer) PrioritizeCandidates(candidates []*RCECandidate) {
	for _, c := range candidates {
		p.scoreCandidate(c)
	}

	// Sort descending by PriorityScore
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].PriorityScore != candidates[j].PriorityScore {
			return candidates[i].PriorityScore > candidates[j].PriorityScore
		}
		return candidates[i].Route < candidates[j].Route
	})
}

func (p *Prioritizer) scoreCandidate(c *RCECandidate) {
	var explanations []string

	// 1. Base Risk by Execution Sink Category
	baseRisk := 20
	switch c.Category {
	case CategoryCommandInjection:
		baseRisk = 30
		explanations = append(explanations, "Command Injection sink carries high intrinsic exploitation severity (+30 base risk)")
	case CategorySSTI:
		baseRisk = 28
		explanations = append(explanations, "Server-Side Template Engine sink provides direct expression evaluation (+28 base risk)")
	case CategoryDeserialization:
		baseRisk = 27
		explanations = append(explanations, "Unsafe object deserialization enables gadget chain invocation (+27 base risk)")
	case CategoryExpressionLanguage:
		baseRisk = 26
		explanations = append(explanations, "Expression language evaluator provides server-side reflection capabilities (+26 base risk)")
	case CategoryFileProcessing:
		baseRisk = 24
		explanations = append(explanations, "Underlying document/image parser (ImageMagick/Ghostscript/FFmpeg) attack surface (+24 base risk)")
	case CategoryBackgroundJob:
		baseRisk = 22
		explanations = append(explanations, "Asynchronous task queue or webhook pipeline execution (+22 base risk)")
	default:
		baseRisk = 20
		explanations = append(explanations, fmt.Sprintf("Standard execution sink category: %s (+20 base risk)", c.Category))
	}

	// 2. Input Exposure Modifier
	inputExp := 5
	paramCount := len(c.RelevantParams) + len(c.RelevantBodyFields)
	if paramCount >= 2 {
		inputExp = 25
		explanations = append(explanations, fmt.Sprintf("Multiple user-controllable inputs (%d parameters/fields) directly reach the sink (+25)", paramCount))
	} else if paramCount == 1 {
		inputExp = 18
		explanations = append(explanations, "Single dedicated parameter directly controls input to the execution sink (+18)")
	} else if strings.Contains(strings.ToLower(c.Route), "upload") {
		inputExp = 20
		explanations = append(explanations, "File upload ingress point exposes binary payload ingestion (+20)")
	} else {
		inputExp = 8
		explanations = append(explanations, "Input inferred primarily from route structure (+8)")
	}

	// 3. Auth Exposure Modifier
	authMod := 10
	// If unauthenticated or anonymous
	isAnon := true
	for _, sig := range c.EvidenceSignals {
		if strings.Contains(strings.ToLower(sig), "auth") || strings.Contains(strings.ToLower(sig), "admin") {
			isAnon = false
			break
		}
	}
	if isAnon {
		authMod = 20
		explanations = append(explanations, "Publicly accessible / unauthenticated execution pathway (+20 exposure)")
	} else {
		authMod = 10
		explanations = append(explanations, "Authenticated or role-constrained endpoint (+10 exposure)")
	}

	// 4. Technology & Advisory Modifier
	techMod := 0
	if len(c.MatchingAdvisories) > 0 {
		highestTier := TierTechDetected
		var topAdv Advisory
		for _, m := range c.MatchingAdvisories {
			if tierRank(m.ProgressionTier) > tierRank(highestTier) {
				highestTier = m.ProgressionTier
				topAdv = m.Advisory
			}
		}

		switch highestTier {
		case TierComponentReachable:
			techMod = 25
			explanations = append(explanations, fmt.Sprintf("Direct CVE reachability match: %s is vulnerable and reachable (+25)", topAdv.ID))
		case TierComponentCorroborated:
			techMod = 20
			explanations = append(explanations, fmt.Sprintf("Vulnerable component corroborated by endpoint functionality: %s (+20)", topAdv.ID))
		case TierVersionAffected:
			techMod = 15
			explanations = append(explanations, fmt.Sprintf("Detected version matches vulnerable range for %s (+15)", topAdv.ID))
		case TierVersionIdentified:
			techMod = 10
			explanations = append(explanations, "Component version identified in technology stack (+10)")
		default:
			techMod = 5
			explanations = append(explanations, "Matching technology family detected (+5)")
		}
	} else if len(c.RelevantTech) > 0 {
		techMod = 5
		explanations = append(explanations, fmt.Sprintf("Relevant backend technologies identified: %s (+5)", strings.Join(c.RelevantTech, ", ")))
	}

	// 5. Processing Chain Modifier
	chainMod := 0
	if len(c.AssociatedChains) > 0 {
		chainMod = 15
		explanations = append(explanations, fmt.Sprintf("Endpoint forms part of %d multi-step processing workflow(s) (+15 chain bonus)", len(c.AssociatedChains)))
	}

	// Calculate total clamped score
	total := baseRisk + inputExp + authMod + techMod + chainMod
	if total > 100 {
		total = 100
	}
	if total < 10 {
		total = 10
	}

	c.PriorityScore = total
	c.ScoreBreakdown = ScoreBreakdown{
		BaseRisk:        baseRisk,
		InputExposure:   inputExp,
		AuthModifier:    authMod,
		TechCVEModifier: techMod,
		ChainModifier:   chainMod,
		TotalScore:      total,
		Explanations:    explanations,
	}
}

func tierRank(t AdvisoryProgressionTier) int {
	switch t {
	case TierComponentReachable:
		return 5
	case TierComponentCorroborated:
		return 4
	case TierVersionAffected:
		return 3
	case TierVersionIdentified:
		return 2
	case TierTechDetected:
		return 1
	}
	return 0
}
