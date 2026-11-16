package rce

import (
	"fmt"
	"strings"
)

// ChainDetector correlates isolated endpoints into multi-step processing workflows.
type ChainDetector struct{}

// NewChainDetector creates a new instance of ChainDetector.
func NewChainDetector() *ChainDetector {
	return &ChainDetector{}
}

// CorrelateChains analyzes candidates within an origin to discover multi-step execution chains.
func (d *ChainDetector) CorrelateChains(candidates []*RCECandidate) {
	// Group candidates by Origin
	byOrigin := make(map[string][]*RCECandidate)
	for _, c := range candidates {
		byOrigin[c.Origin] = append(byOrigin[c.Origin], c)
	}

	for _, list := range byOrigin {
		d.correlateOrigin(list)
	}
}

func (d *ChainDetector) correlateOrigin(list []*RCECandidate) {
	// Find upload endpoints
	var uploadCands []*RCECandidate
	var previewConvertCands []*RCECandidate
	var jobCands []*RCECandidate

	for _, c := range list {
		route := strings.ToLower(c.Route)
		if strings.Contains(route, "upload") || c.Category == CategoryFileProcessing {
			uploadCands = append(uploadCands, c)
		}
		if strings.Contains(route, "convert") || strings.Contains(route, "preview") ||
			strings.Contains(route, "thumbnail") || strings.Contains(route, "pdf") ||
			strings.Contains(route, "extract") {
			previewConvertCands = append(previewConvertCands, c)
		}
		if c.Category == CategoryBackgroundJob || strings.Contains(route, "queue") ||
			strings.Contains(route, "worker") || strings.Contains(route, "cron") ||
			strings.Contains(route, "deploy") {
			jobCands = append(jobCands, c)
		}
	}

	// 1. Detect File Upload -> Document Conversion / Preview Chain
	for _, up := range uploadCands {
		for _, pc := range previewConvertCands {
			if up.ID == pc.ID {
				continue
			}

			// Check for shared parameters (e.g. file, doc_id, filename, id) or shared path prefixes
			sharedParam := findSharedParam(up, pc)
			sharedPrefix := findSharedPrefix(up.Route, pc.Route)

			if sharedParam != "" || sharedPrefix {
				chainID := fmt.Sprintf("chain_fileproc_%s_%s", up.ID, pc.ID)
				name := "File Upload -> Document Processing / Conversion Chain"
				desc := fmt.Sprintf("File uploaded via '%s' flows into document conversion/preview processing at '%s'",
					up.Route, pc.Route)

				chain := ProcessingChain{
					ChainID:     chainID,
					Name:        name,
					Description: desc,
					Steps: []ProcessingStep{
						{
							EndpointID: up.ID,
							Route:      up.Route,
							Method:     up.HTTPMethod,
							Role:       "upload_source",
							DataFlow:   "Receives external file payload and persists reference",
						},
						{
							EndpointID: pc.ID,
							Route:      pc.Route,
							Method:     pc.HTTPMethod,
							Role:       "parser_converter_sink",
							DataFlow:   "Parses uploaded document via external conversion utility (ImageMagick/LibreOffice/Ghostscript)",
						},
					},
				}

				attachChain(up, chain)
				attachChain(pc, chain)
			}
		}
	}

	// 2. Detect Upload / Template / Task Config -> Asynchronous Worker Job Chain
	for _, up := range append(uploadCands, previewConvertCands...) {
		for _, jc := range jobCands {
			if up.ID == jc.ID {
				continue
			}

			sharedPrefix := findSharedPrefix(up.Route, jc.Route)
			if sharedPrefix {
				chainID := fmt.Sprintf("chain_asyncjob_%s_%s", up.ID, jc.ID)
				name := "Ingestion -> Asynchronous Background Execution Chain"
				desc := fmt.Sprintf("Payload received at '%s' is dispatched into background worker queue at '%s'",
					up.Route, jc.Route)

				chain := ProcessingChain{
					ChainID:     chainID,
					Name:        name,
					Description: desc,
					Steps: []ProcessingStep{
						{
							EndpointID: up.ID,
							Route:      up.Route,
							Method:     up.HTTPMethod,
							Role:       "data_ingress",
							DataFlow:   "Ingests user-controlled payload or configuration",
						},
						{
							EndpointID: jc.ID,
							Route:      jc.Route,
							Method:     jc.HTTPMethod,
							Role:       "async_worker_sink",
							DataFlow:   "Dispatches task into background execution worker or shell runner",
						},
					},
				}

				attachChain(up, chain)
				attachChain(jc, chain)
			}
		}
	}
}

func findSharedParam(a, b *RCECandidate) string {
	for _, pa := range append(a.RelevantParams, a.RelevantBodyFields...) {
		paL := strings.ToLower(pa)
		for _, pb := range append(b.RelevantParams, b.RelevantBodyFields...) {
			pbL := strings.ToLower(pb)
			if paL == pbL && len(paL) > 2 {
				return pa
			}
		}
	}
	return ""
}

func findSharedPrefix(routeA, routeB string) bool {
	partsA := strings.Split(strings.Trim(routeA, "/"), "/")
	partsB := strings.Split(strings.Trim(routeB, "/"), "/")
	if len(partsA) >= 2 && len(partsB) >= 2 {
		return partsA[0] == partsB[0] && partsA[1] == partsB[1]
	}
	if len(partsA) >= 1 && len(partsB) >= 1 {
		return partsA[0] == partsB[0]
	}
	return false
}

func attachChain(c *RCECandidate, chain ProcessingChain) {
	for _, existing := range c.AssociatedChains {
		if existing.ChainID == chain.ChainID {
			return
		}
	}
	c.AssociatedChains = append(c.AssociatedChains, chain)
}
