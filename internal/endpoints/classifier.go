package endpoints

import (
	"fmt"
	"strings"
)

// ClassifyEndpoint applies deterministic heuristics to categorize the attack surface of an endpoint.
// IMPORTANT: Functional classification indicates suspected attack surface for research prioritization.
// It is strictly non-authoritative and does NOT represent an identified vulnerability or confirmed exploitability.
// An endpoint classified as 'file_process' is a candidate for file handling research, not an RCE finding.
func ClassifyEndpoint(route string, queryParams []string, bodyFields []string, contentTypes []string) []ClassificationResult {
	routeLower := strings.ToLower(route)
	paramsLower := strings.ToLower(strings.Join(queryParams, " "))
	fieldsLower := strings.ToLower(strings.Join(bodyFields, " "))
	contentLower := strings.ToLower(strings.Join(contentTypes, " "))

	var results []ClassificationResult

	// Helper to evaluate a category
	evaluate := func(category FunctionClassification, basePriority int, routeMatches []string, paramMatches []string, fieldMatches []string, contentMatches []string) {
		var signals []string
		routeHit := false
		paramHit := false
		fieldHit := false
		contentHit := false

		for _, rm := range routeMatches {
			if strings.Contains(routeLower, rm) {
				signals = append(signals, fmt.Sprintf("route contains '%s'", rm))
				routeHit = true
			}
		}
		for _, pm := range paramMatches {
			if containsWord(paramsLower, pm) {
				signals = append(signals, fmt.Sprintf("query param contains '%s'", pm))
				paramHit = true
			}
		}
		for _, fm := range fieldMatches {
			if containsWord(fieldsLower, fm) {
				signals = append(signals, fmt.Sprintf("body field contains '%s'", fm))
				fieldHit = true
			}
		}
		for _, cm := range contentMatches {
			if strings.Contains(contentLower, cm) {
				signals = append(signals, fmt.Sprintf("content-type contains '%s'", cm))
				contentHit = true
			}
		}

		if len(signals) == 0 {
			return
		}

		// Calculate confidence based on multi-source correlation
		confidence := ConfidenceLow
		signalSources := 0
		if routeHit {
			signalSources++
		}
		if paramHit {
			signalSources++
		}
		if fieldHit {
			signalSources++
		}
		if contentHit {
			signalSources++
		}

		// Multi-source correlation produces high confidence
		if signalSources >= 2 {
			confidence = ConfidenceHigh
		} else if routeHit || len(signals) >= 2 {
			confidence = ConfidenceMedium
		}

		results = append(results, ClassificationResult{
			Category:        category,
			Confidence:      confidence,
			EvidenceSignals: signals,
			Priority:        basePriority,
		})
	}

	// 1. File processing (Research priority 9: candidate for file parsing / path traversal / upload attacks)
	evaluate(ClassFileProcess, 9,
		[]string{"/upload", "/file", "/attachment", "/document", "/media", "/avatar", "/asset"},
		[]string{"file", "upload", "attachment", "doc", "filename"},
		[]string{"file", "upload", "attachment", "filename"},
		[]string{"multipart/form-data"},
	)

	// 2. Document conversion (Research priority 9: candidate for SSRF / ghostscript / headless browser / pandoc RCE)
	evaluate(ClassDocConvert, 9,
		[]string{"/convert", "/pdf", "/html2pdf", "/doc2pdf", "/render-pdf", "/export-pdf", "/print", "/preview-doc"},
		[]string{"format", "convert", "to_pdf", "engine"},
		[]string{"format", "convert", "target_format"},
		nil,
	)

	// 3. Template rendering (Research priority 9: candidate for SSTI / template engine execution)
	evaluate(ClassTemplateRender, 9,
		[]string{"/template", "/render", "/preview", "/mail-template", "/email/preview", "/jinja", "/freemarker", "/thymeleaf", "/blade", "/twig"},
		[]string{"template", "tpl", "theme", "view", "layout"},
		[]string{"template", "tpl", "body_template", "content_template"},
		nil,
	)

	// 4. Archive extraction (Research priority 9: candidate for zip slip / tar bomb / archive traversal)
	evaluate(ClassArchiveExtract, 9,
		[]string{"/unzip", "/extract", "/archive", "/unpack", "/tar", "/zip", "/compress", "/decompress"},
		[]string{"archive", "zip", "tar"},
		[]string{"archive", "zip", "extract"},
		nil,
	)

	// 5. Import/Export (Research priority 7: candidate for CSV injection, XML external entity, batch processing)
	evaluate(ClassImportExport, 7,
		[]string{"/import", "/export", "/csv", "/xml", "/json-export", "/download-report", "/data-export", "/backup", "/dump"},
		[]string{"export", "import", "download", "report_type"},
		[]string{"import_data", "export_format"},
		nil,
	)

	// 6. Image processing (Research priority 6: candidate for ImageMagick, libvips, graphics libraries)
	evaluate(ClassImageProcess, 6,
		[]string{"/image", "/photo", "/thumbnail", "/resize", "/crop", "/filter", "/avatar/edit", "/watermark"},
		[]string{"width", "height", "resize", "crop", "dimensions", "scale"},
		[]string{"width", "height", "resize", "crop"},
		nil,
	)

	// 7. Background jobs (Research priority 6: candidate for async task injection / serialized payloads)
	evaluate(ClassBackgroundJob, 6,
		[]string{"/job", "/queue", "/task", "/async", "/worker", "/batch", "/schedule", "/cron"},
		[]string{"job_id", "task_id", "queue"},
		nil,
		nil,
	)

	// 8. Webhooks (Research priority 5: candidate for SSRF / signature bypass)
	evaluate(ClassWebhook, 5,
		[]string{"/webhook", "/callback", "/hook", "/event", "/listener", "/notify", "/incoming"},
		nil,
		nil,
		nil,
	)

	// 9. Build and workflow functionality (Research priority 10: candidate for pipeline execution / CI/CD command injection)
	evaluate(ClassBuildWorkflow, 10,
		[]string{"/build", "/deploy", "/ci", "/pipeline", "/workflow", "/action", "/runner", "/execute", "/script"},
		[]string{"pipeline_id", "build_id", "commit", "branch"},
		nil,
		nil,
	)

	// 10. User data (Research priority 8: prime candidate for IDOR & object authorization testing)
	evaluate(ClassUserData, 8,
		[]string{"/user", "/account", "/profile", "/customer", "/client", "/member", "/me", "/billing", "/order", "/invoice", "/wallet", "/payment", "/setting"},
		[]string{"user_id", "account_id", "profile_id", "customer_id", "order_id", "invoice_id"},
		[]string{"user_id", "account_id", "profile_id", "customer_id"},
		nil,
	)

	// 11. Admin & Internal (Research priority 8: candidate for privilege escalation / admin bypass)
	evaluate(ClassAdmin, 8,
		[]string{"/admin", "/manage", "/dashboard", "/internal", "/system", "/root", "/console", "/ops"},
		nil,
		nil,
		nil,
	)

	// 12. Authentication & Sessions (Research priority 4: authentication flows)
	evaluate(ClassAuth, 4,
		[]string{"/login", "/logout", "/signin", "/signup", "/auth", "/oauth", "/token", "/session", "/password", "/register"},
		nil,
		nil,
		nil,
	)

	// Default fallback if no specific attack surface detected
	if len(results) == 0 {
		results = append(results, ClassificationResult{
			Category:        ClassGeneralAPI,
			Confidence:      ConfidenceLow,
			EvidenceSignals: []string{"standard API route"},
			Priority:        2,
		})
	}

	return results
}

func containsWord(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
