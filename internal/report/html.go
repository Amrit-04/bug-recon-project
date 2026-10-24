package report

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

// GenerateHTML produces a self-contained, interactive HTML report with light/dark theme toggle.
func GenerateHTML(target string, list []*validate.ValidatedFinding) string {
	var verified, manual, suppressed int
	sevCount := map[findings.Severity]int{}

	for _, vf := range list {
		switch vf.Status {
		case validate.StatusVerified:
			verified++
			sevCount[vf.Finding.Severity]++
		case validate.StatusNeedsManualReview:
			manual++
		case validate.StatusSuppressed:
			suppressed++
		}
	}

	var verifiedCards strings.Builder
	for i, vf := range list {
		if vf.Status != validate.StatusVerified {
			continue
		}
		f := vf.Finding

		badgeClass := "badge-info"
		switch f.Severity {
		case findings.SeverityHigh:
			badgeClass = "badge-high"
		case findings.SeverityMedium:
			badgeClass = "badge-medium"
		case findings.SeverityLow:
			badgeClass = "badge-low"
		}

		pathsStr := f.Path
		if len(vf.AffectedPaths) > 0 {
			pathsStr = strings.Join(vf.AffectedPaths, ", ")
		}

		var refsHTML strings.Builder
		for _, ref := range f.References {
			refsHTML.WriteString(fmt.Sprintf(`<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, html.EscapeString(ref), html.EscapeString(ref)))
		}

		evidenceHTML := ""
		if f.Evidence != "" || f.Response != "" {
			ev := f.Evidence
			if ev == "" {
				ev = f.Response
			}
			evidenceHTML = fmt.Sprintf(`
			<details class="evidence-box">
				<summary>View Redacted Evidence</summary>
				<pre><code>%s</code></pre>
			</details>`, html.EscapeString(ev))
		}

		verifiedCards.WriteString(fmt.Sprintf(`
		<div class="card">
			<div class="card-header">
				<span class="badge %s">%s</span>
				<h3>#%d %s</h3>
			</div>
			<div class="card-body">
				<p><strong>Target:</strong> <code>%s</code> | <strong>Path:</strong> <code>%s</code></p>
				<p><strong>Rule ID:</strong> <code>%s</code> | <strong>Check:</strong> %s</p>
				<p><strong>Impact:</strong> %s</p>
				<div class="remediation">
					<strong>Remediation Guidance:</strong>
					<p>%s</p>
				</div>
				%s
				%s
			</div>
		</div>`,
			badgeClass, html.EscapeString(strings.ToUpper(string(f.Severity))),
			i+1, html.EscapeString(f.Title),
			html.EscapeString(f.Target), html.EscapeString(pathsStr),
			html.EscapeString(f.RuleID), html.EscapeString(f.CheckName),
			html.EscapeString(f.Impact),
			html.EscapeString(f.Remediation),
			evidenceHTML,
			func() string {
				if refsHTML.Len() > 0 {
					return fmt.Sprintf("<div class='references'><strong>References:</strong><ul>%s</ul></div>", refsHTML.String())
				}
				return ""
			}(),
		))
	}

	htmlTemplate := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>scoutr Report — %s</title>
<style>
:root {
  --bg-primary: #0f172a;
  --bg-secondary: #1e293b;
  --bg-card: #1e293b;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --border: #334155;
  --high: #ef4444;
  --medium: #f97316;
  --low: #3b82f6;
  --info: #64748b;
  --success: #10b981;
}
[data-theme="light"] {
  --bg-primary: #f8fafc;
  --bg-secondary: #ffffff;
  --bg-card: #ffffff;
  --text-primary: #0f172a;
  --text-secondary: #64748b;
  --border: #e2e8f0;
}
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg-primary);
  color: var(--text-primary);
  margin: 0;
  padding: 2rem;
  line-height: 1.5;
}
.container { max-width: 1000px; margin: 0 auto; }
header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; }
.theme-toggle { background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.metric-box { background: var(--bg-card); border: 1px solid var(--border); padding: 1.2rem; border-radius: 8px; text-align: center; }
.metric-num { font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
.card-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 1rem; }
.card-header h3 { margin: 0; font-size: 1.1rem; }
.card-body { padding: 1.5rem; }
.badge { padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: white; }
.badge-high { background-color: var(--high); }
.badge-medium { background-color: var(--medium); }
.badge-low { background-color: var(--low); }
.badge-info { background-color: var(--info); }
.remediation { background: rgba(59, 130, 246, 0.1); border-left: 4px solid var(--low); padding: 1rem; border-radius: 4px; margin: 1rem 0; }
.evidence-box { margin-top: 1rem; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem 1rem; }
.evidence-box summary { cursor: pointer; font-weight: 500; color: var(--text-secondary); }
pre { overflow-x: auto; font-family: monospace; font-size: 0.85rem; padding: 0.5rem 0; margin: 0; }
code { background: rgba(148, 163, 184, 0.15); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container">
<header>
  <div>
    <h1>scoutr Security Audit Report</h1>
    <p style="color: var(--text-secondary); margin: 0;">Target: <strong>%s</strong> &bull; Generated: %s</p>
  </div>
  <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Mode</button>
</header>

<div class="metrics">
  <div class="metric-box"><div>Verified Findings</div><div class="metric-num" style="color: var(--high);">%d</div></div>
  <div class="metric-box"><div>Needs Manual Review</div><div class="metric-num" style="color: var(--medium);">%d</div></div>
  <div class="metric-box"><div>Suppressed</div><div class="metric-num" style="color: var(--info);">%d</div></div>
</div>

<h2>Verified Findings</h2>
%s

</div>
<script>
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
}
</script>
</body>
</html>`,
		html.EscapeString(target),
		html.EscapeString(target),
		time.Now().Format("2006-01-02 15:04:05 MST"),
		verified, manual, suppressed,
		func() string {
			if verifiedCards.Len() == 0 {
				return "<p style='color: var(--text-secondary);'>No verified findings detected.</p>"
			}
			return verifiedCards.String()
		}(),
	)

	return htmlTemplate
}
