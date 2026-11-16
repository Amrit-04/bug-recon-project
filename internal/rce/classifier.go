package rce

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/endpoints"
)

// Classifier discovers RCE attack surfaces from endpoint intelligence.
type Classifier struct{}

// NewClassifier creates an instance of the attack-surface classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Regex patterns for signal identification
var (
	// File processing patterns
	fileRouteRegex         = regexp.MustCompile(`(?i)/(upload|convert|preview|thumbnail|render_pdf|pdf|export_doc|doc|docx|image|resize|transcode|archive|extract|import_file|ocr|scanner|avatar|media)`)
	fileParamRegex         = regexp.MustCompile(`(?i)^(file|filename|filepath|doc|document|pdf|image|img|archive|zip|tar|upload|attachment)$`)
	fileModifierParamRegex = regexp.MustCompile(`(?i)^(format|target_format|preset)$`)

	// SSTI patterns
	sstiRouteRegex = regexp.MustCompile(`(?i)/(template|render|preview_template|email_preview|notification|report_view|mailer|generate_page|cms|layout)`)
	sstiParamRegex = regexp.MustCompile(`(?i)^(template|tpl|content|layout|markup|body|html|theme|markdown|email_body|greeting|msg_template)$`)

	// Command injection patterns
	cmdRouteRegex = regexp.MustCompile(`(?i)/(ping|traceroute|dig|dns_lookup|network_test|system_info|diag|diagnostics|exec|run_cmd|shell|backup|restore|dump|db_export|git_clone|repo_sync|build_agent)`)
	cmdParamRegex = regexp.MustCompile(`(?i)^(cmd|command|exec|ip|host|hostname|target|domain|address|tool|utility|backup_path|db_name|repo_url|git_url|branch|script|args|flags)$`)

	// Deserialization patterns
	deserRouteRegex = regexp.MustCompile(`(?i)/(deserialize|restore_session|load_state|import_config|yaml_parser|xml_import|fastjson|object_import)`)
	deserParamRegex = regexp.MustCompile(`(?i)^(data|state|session_data|payload|serialized|obj|object|config_yaml|xml_data|viewstate|b64_data)$`)

	// Expression language patterns
	elRouteRegex = regexp.MustCompile(`(?i)/(eval|evaluate|calc|formula|query_eval|rules|expression|condition|filter_expr|spel|ognl)`)
	elParamRegex = regexp.MustCompile(`(?i)^(expr|expression|eval|formula|calc|condition|rule|query|code|script|filter_code)$`)

	// Background job patterns
	jobRouteRegex = regexp.MustCompile(`(?i)/(webhook|hook|callback|schedule_task|queue_job|worker|dispatch|cron|trigger_build|pipeline_run|deploy_hook)`)
	jobParamRegex = regexp.MustCompile(`(?i)^(webhook_url|callback_url|job_name|task_payload|cron_expr|pipeline_id|runner_tag|deploy_script)$`)
)

// ClassifyEndpoints inspects an inventory of endpoints and produces candidate RCE hypotheses.
func (c *Classifier) ClassifyEndpoints(target string, eps []*endpoints.Endpoint) []*RCECandidate {
	var candidates []*RCECandidate
	seen := make(map[string]bool)

	for _, ep := range eps {
		if ep == nil {
			continue
		}

		// Inspect all categories for this endpoint
		candList := c.inspectEndpoint(target, ep)
		for _, cand := range candList {
			key := cand.Key()
			if !seen[key] {
				seen[key] = true
				candidates = append(candidates, cand)
			}
		}
	}

	return candidates
}

func (c *Classifier) inspectEndpoint(target string, ep *endpoints.Endpoint) []*RCECandidate {
	var candidates []*RCECandidate
	route := strings.ToLower(ep.NormalizedRoute)
	method := "GET"
	if len(ep.Methods) > 0 {
		method = strings.ToUpper(ep.Methods[0])
	}

	// 1. Check Command Injection candidates
	if cmdCand := c.checkCommandInjection(target, ep, route, method); cmdCand != nil {
		candidates = append(candidates, cmdCand)
	}

	// 2. Check SSTI candidates
	if sstiCand := c.checkSSTI(target, ep, route, method); sstiCand != nil {
		candidates = append(candidates, sstiCand)
	}

	// 3. Check File Processing candidates
	if fileCand := c.checkFileProcessing(target, ep, route, method); fileCand != nil {
		candidates = append(candidates, fileCand)
	}

	// 4. Check Deserialization candidates
	if deserCand := c.checkDeserialization(target, ep, route, method); deserCand != nil {
		candidates = append(candidates, deserCand)
	}

	// 5. Check Expression Language candidates
	if elCand := c.checkExpressionLanguage(target, ep, route, method); elCand != nil {
		candidates = append(candidates, elCand)
	}

	// 6. Check Background Job / Automation candidates
	if jobCand := c.checkBackgroundJob(target, ep, route, method); jobCand != nil {
		candidates = append(candidates, jobCand)
	}

	return candidates
}

func (c *Classifier) checkCommandInjection(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string

	for _, p := range ep.QueryParams {
		if cmdParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' matches command execution input patterns", p))
		}
	}
	for _, f := range ep.BodyFields {
		if cmdParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			evidence = append(evidence, fmt.Sprintf("Request body field '%s' matches command execution input patterns", f))
		}
	}

	routeMatch := cmdRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates system/diagnostic/backup command invocation", ep.NormalizedRoute))
	}

	if len(matchedParams) == 0 && !routeMatch {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "OS Command Invocation (system, exec, popen, Runtime.exec)"
	hypothesis := fmt.Sprintf("Untrusted input provided via %s may be concatenated into shell command strings without shell escaping.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategoryCommandInjection, "System Utility / Diagnostic Invocation",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) checkSSTI(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string

	for _, p := range ep.QueryParams {
		if sstiParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' matches template injection patterns", p))
		}
	}
	for _, f := range ep.BodyFields {
		if sstiParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			evidence = append(evidence, fmt.Sprintf("Request body field '%s' matches template injection patterns", f))
		}
	}

	routeMatch := sstiRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates server-side template rendering or dynamic page generation", ep.NormalizedRoute))
	}

	// Check if known template engines are present in tech fingerprints
	for _, t := range ep.TechFingerprints {
		tl := strings.ToLower(t)
		if strings.Contains(tl, "jinja") || strings.Contains(tl, "twig") || strings.Contains(tl, "freemarker") ||
			strings.Contains(tl, "thymeleaf") || strings.Contains(tl, "smarty") || strings.Contains(tl, "erb") ||
			strings.Contains(tl, "blade") || strings.Contains(tl, "velocity") {
			evidence = append(evidence, fmt.Sprintf("Detected template engine technology: %s", t))
		}
	}

	if len(matchedParams) == 0 && !routeMatch {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "Server-Side Template Engine (Jinja2, Twig, Freemarker, Thymeleaf, ERB)"
	hypothesis := fmt.Sprintf("User-controlled template string passed in %s may be evaluated directly by the template engine, allowing sandbox escape.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategorySSTI, "Server-Side Template Rendering",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) checkFileProcessing(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string
	hasFileParam := false

	for _, p := range ep.QueryParams {
		if fileParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			hasFileParam = true
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' references file processing operations", p))
		} else if fileModifierParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
		}
	}
	for _, f := range ep.BodyFields {
		if fileParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			hasFileParam = true
			evidence = append(evidence, fmt.Sprintf("Body field '%s' indicates uploaded file or document", f))
		} else if fileModifierParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
		}
	}

	routeMatch := fileRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates file upload, conversion, or document processing", ep.NormalizedRoute))
	}

	hasMultipart := false
	for _, ct := range ep.ContentTypes {
		ctl := strings.ToLower(ct)
		if strings.Contains(ctl, "multipart/form-data") {
			hasMultipart = true
			evidence = append(evidence, "Endpoint accepts multipart/form-data file uploads")
		}
	}

	if !routeMatch && !hasFileParam && !hasMultipart {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "Underlying File Processing Utilities (ImageMagick, Ghostscript, FFmpeg, LibreOffice, Tar/Zip)"
	hypothesis := fmt.Sprintf("Uploaded document or format parameter in %s may be processed by vulnerable external parsers or conversion binaries.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategoryFileProcessing, "File Upload & Conversion Pipeline",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) checkDeserialization(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string

	for _, p := range ep.QueryParams {
		if deserParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' references serialized data", p))
		}
	}
	for _, f := range ep.BodyFields {
		if deserParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			evidence = append(evidence, fmt.Sprintf("Body field '%s' references serialized state or object payload", f))
		}
	}

	for _, ct := range ep.ContentTypes {
		ctl := strings.ToLower(ct)
		if strings.Contains(ctl, "x-java-serialized") || strings.Contains(ctl, "x-yaml") {
			evidence = append(evidence, fmt.Sprintf("Observed serialized Content-Type: %s", ct))
		}
	}

	routeMatch := deserRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates object reconstruction or state deserialization", ep.NormalizedRoute))
	}

	if len(matchedParams) == 0 && !routeMatch {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "Object Deserialization Runtime (Java ObjectInputStream, Python pickle, PHP unserialize, Ruby Marshal)"
	hypothesis := fmt.Sprintf("Serialized object data passed via %s may be deserialized without type whitelisting, enabling gadget chain execution.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategoryDeserialization, "Object Deserialization & State Import",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) checkExpressionLanguage(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string

	for _, p := range ep.QueryParams {
		if elParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' indicates formula or expression input", p))
		}
	}
	for _, f := range ep.BodyFields {
		if elParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			evidence = append(evidence, fmt.Sprintf("Body field '%s' indicates formula or dynamic query input", f))
		}
	}

	routeMatch := elRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates expression evaluation or dynamic formula execution", ep.NormalizedRoute))
	}

	if len(matchedParams) == 0 && !routeMatch {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "Expression Language Evaluator (Spring SpEL, Apache Struts OGNL, MVEL, JEXL, ScriptEngine)"
	hypothesis := fmt.Sprintf("Expression or formula parameter provided in %s may be evaluated server-side by an unconstrained EL evaluator.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategoryExpressionLanguage, "Dynamic Expression & Formula Evaluation",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) checkBackgroundJob(target string, ep *endpoints.Endpoint, route, method string) *RCECandidate {
	var matchedParams []string
	var evidence []string

	for _, p := range ep.QueryParams {
		if jobParamRegex.MatchString(p) {
			matchedParams = append(matchedParams, p)
			evidence = append(evidence, fmt.Sprintf("Query parameter '%s' references background job or webhook dispatch", p))
		}
	}
	for _, f := range ep.BodyFields {
		if jobParamRegex.MatchString(f) {
			matchedParams = append(matchedParams, f)
			evidence = append(evidence, fmt.Sprintf("Body field '%s' references background task queue or runner payload", f))
		}
	}

	routeMatch := jobRouteRegex.MatchString(route)
	if routeMatch {
		evidence = append(evidence, fmt.Sprintf("Route '%s' indicates webhook, automation workflow, or worker dispatch", ep.NormalizedRoute))
	}

	if len(matchedParams) == 0 && !routeMatch {
		return nil
	}

	conf := ConfidenceMedium
	if routeMatch && len(matchedParams) > 0 {
		conf = ConfidenceHigh
	} else if len(matchedParams) == 0 {
		conf = ConfidenceLow
	}

	sink := "Asynchronous Worker Queue / Task Automation Engine (Celery, BullMQ, Sidekiq, CI/CD Runner)"
	hypothesis := fmt.Sprintf("Worker task or webhook parameters in %s may be dispatched into asynchronous worker tasks that execute system operations.",
		summarizeInputs(matchedParams))

	return c.buildCandidate(target, ep, method, CategoryBackgroundJob, "Background Automation & Webhook Dispatch",
		hypothesis, sink, matchedParams, ep.BodyFields, ep.TechFingerprints, evidence, conf)
}

func (c *Classifier) buildCandidate(
	target string,
	ep *endpoints.Endpoint,
	method string,
	cat RCECategory,
	featureType string,
	hypothesis string,
	sink string,
	params []string,
	bodyFields []string,
	tech []string,
	evidence []string,
	conf RCEConfidence,
) *RCECandidate {
	candID := fmt.Sprintf("rce_%s_%s_%s", string(cat)[:4], sanitizeID(ep.NormalizedRoute), method)
	origin := ep.Origin
	if origin == "" && ep.URL != "" {
		if u, err := url.Parse(ep.URL); err == nil {
			origin = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	if origin == "" {
		origin = "https://" + target
	}

	src := "endpoint_intelligence"
	if len(ep.Sources) > 0 {
		src = ep.Sources[0]
	}

	now := time.Now()
	cand := &RCECandidate{
		ID:                 candID,
		Target:             target,
		Origin:             origin,
		Route:              ep.NormalizedRoute,
		HTTPMethod:         method,
		Category:           cat,
		FeatureType:        featureType,
		Hypothesis:         hypothesis,
		SuspectedSink:      sink,
		RelevantParams:     params,
		RelevantBodyFields: bodyFields,
		RelevantTech:       tech,
		DiscoverySource:    src,
		EvidenceSignals:    evidence,
		Confidence:         conf,
		ValidationStatus:   StatusCandidate,
		DiscoveredAt:       now,
		UpdatedAt:          now,
	}

	return cand
}

func summarizeInputs(params []string) string {
	if len(params) == 0 {
		return "endpoint parameters"
	}
	return fmt.Sprintf("parameters [%s]", strings.Join(params, ", "))
}

func sanitizeID(route string) string {
	clean := strings.ReplaceAll(route, "/", "_")
	clean = strings.ReplaceAll(clean, "{", "")
	clean = strings.ReplaceAll(clean, "}", "")
	clean = strings.ReplaceAll(clean, "-", "_")
	clean = strings.Trim(clean, "_")
	if len(clean) > 25 {
		clean = clean[:25]
	}
	if clean == "" {
		clean = "root"
	}
	return clean
}
