package cli

import "testing"

func TestScanRequiresPostureVerification(t *testing.T) {
	// `scan` has no built-in checks, so running it without the opt-in nuclei
	// stage would inspect nothing and then report a clean scan.
	if err := scanPrecondition(false); err == nil {
		t.Fatal("expected scan without --verify-posture to be refused")
	}
	if err := scanPrecondition(true); err != nil {
		t.Fatalf("expected --verify-posture to be accepted, got %v", err)
	}
}
