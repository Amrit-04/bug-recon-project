package cli

import (
	"testing"

	"github.com/scoutr/scoutr/internal/tools"
)

// nmap rows for ports naabu never reported must not widen the port set.
func TestMergeServiceFingerprintsKeepsNaabuPortSet(t *testing.T) {
	ports := []tools.PortResult{
		{Host: "example.com", Port: 443, Source: "naabu"},
		{Host: "example.com", Port: 80, Source: "naabu"},
	}
	services := []tools.PortResult{
		{Host: "example.com", Port: 443, Service: "https", Product: "nginx", Version: "1.25"},
		{Host: "example.com", Port: 8080, Service: "http-proxy"},
	}

	merged := mergeServiceFingerprints(ports, services)

	if len(merged) != 2 {
		t.Fatalf("merged port count = %d, want 2 (naabu set only): %+v", len(merged), merged)
	}
	if merged[0].Port != 80 || merged[1].Port != 443 {
		t.Fatalf("ports were not sorted by port: %+v", merged)
	}
	if got := merged[1]; got.Service != "https" || got.Product != "nginx" || got.Version != "1.25" {
		t.Errorf("nmap fingerprint was not merged: %+v", got)
	}
	if got := merged[1].Source; got != "naabu+nmap" {
		t.Errorf("source = %q, want naabu+nmap", got)
	}
}
