package endpoints

import (
	"strings"
)

// ClassifyEndpoint applies deterministic heuristics to categorize the functionality of an endpoint.
func ClassifyEndpoint(route string, queryParams []string, bodyFields []string, contentTypes []string) []FunctionClassification {
	routeLower := strings.ToLower(route)
	paramsLower := strings.ToLower(strings.Join(queryParams, " "))
	fieldsLower := strings.ToLower(strings.Join(bodyFields, " "))
	contentLower := strings.ToLower(strings.Join(contentTypes, " "))

	seen := make(map[FunctionClassification]bool)
	var classes []FunctionClassification

	addClass := func(c FunctionClassification) {
		if !seen[c] {
			seen[c] = true
			classes = append(classes, c)
		}
	}

	// 1. File processing
	if containsAny(routeLower, "/upload", "/file", "/attachment", "/document", "/media", "/avatar", "/asset") ||
		containsAny(paramsLower, "file", "upload", "attachment", "doc", "filename") ||
		containsAny(fieldsLower, "file", "upload", "attachment", "filename") ||
		strings.Contains(contentLower, "multipart/form-data") {
		addClass(ClassFileProcess)
	}

	// 2. Document conversion
	if containsAny(routeLower, "/convert", "/pdf", "/html2pdf", "/doc2pdf", "/render-pdf", "/export-pdf", "/print", "/preview-doc") ||
		containsAny(paramsLower, "format", "convert", "to_pdf", "engine") ||
		containsAny(fieldsLower, "format", "convert", "target_format") {
		addClass(ClassDocConvert)
	}

	// 3. Template rendering
	if containsAny(routeLower, "/template", "/render", "/preview", "/view", "/mail-template", "/email/preview", "/jinja", "/freemarker", "/thymeleaf", "/blade", "/twig") ||
		containsAny(paramsLower, "template", "tpl", "theme", "view", "layout") ||
		containsAny(fieldsLower, "template", "tpl", "body_template", "content_template") {
		addClass(ClassTemplateRender)
	}

	// 4. Archive extraction
	if containsAny(routeLower, "/unzip", "/extract", "/archive", "/unpack", "/tar", "/zip", "/compress", "/decompress") ||
		containsAny(paramsLower, "archive", "zip", "tar") ||
		containsAny(fieldsLower, "archive", "zip", "extract") {
		addClass(ClassArchiveExtract)
	}

	// 5. Import/Export
	if containsAny(routeLower, "/import", "/export", "/csv", "/xml", "/json-export", "/download-report", "/data-export", "/backup", "/dump") ||
		containsAny(paramsLower, "export", "import", "download", "report_type") ||
		containsAny(fieldsLower, "import_data", "export_format") {
		addClass(ClassImportExport)
	}

	// 6. Image processing
	if containsAny(routeLower, "/image", "/photo", "/thumbnail", "/resize", "/crop", "/filter", "/avatar/edit", "/watermark") ||
		containsAny(paramsLower, "width", "height", "resize", "crop", "dimensions", "scale") ||
		containsAny(fieldsLower, "width", "height", "resize", "crop") {
		addClass(ClassImageProcess)
	}

	// 7. Background jobs
	if containsAny(routeLower, "/job", "/queue", "/task", "/async", "/worker", "/batch", "/schedule", "/cron") ||
		containsAny(paramsLower, "job_id", "task_id", "queue") {
		addClass(ClassBackgroundJob)
	}

	// 8. Webhooks
	if containsAny(routeLower, "/webhook", "/callback", "/hook", "/event", "/listener", "/notify", "/incoming") {
		addClass(ClassWebhook)
	}

	// 9. Build and workflow functionality
	if containsAny(routeLower, "/build", "/deploy", "/ci", "/pipeline", "/workflow", "/action", "/runner", "/execute", "/script") ||
		containsAny(paramsLower, "pipeline_id", "build_id", "commit", "branch") {
		addClass(ClassBuildWorkflow)
	}

	// 10. User data (High value for IDOR)
	if containsAny(routeLower, "/user", "/account", "/profile", "/customer", "/client", "/member", "/me", "/billing", "/order", "/invoice", "/wallet", "/payment", "/setting") ||
		containsAny(paramsLower, "user_id", "account_id", "profile_id", "customer_id", "order_id", "invoice_id") ||
		containsAny(fieldsLower, "user_id", "account_id", "profile_id", "customer_id") {
		addClass(ClassUserData)
	}

	// 11. Admin & Internal
	if containsAny(routeLower, "/admin", "/manage", "/dashboard", "/internal", "/system", "/root", "/console", "/ops") {
		addClass(ClassAdmin)
	}

	// 12. Authentication & Sessions
	if containsAny(routeLower, "/login", "/logout", "/signin", "/signup", "/auth", "/oauth", "/token", "/session", "/password", "/register") {
		addClass(ClassAuth)
	}

	// Default fallback
	if len(classes) == 0 {
		addClass(ClassGeneralAPI)
	}

	return classes
}

func containsAny(s string, sub ...string) bool {
	for _, item := range sub {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}
