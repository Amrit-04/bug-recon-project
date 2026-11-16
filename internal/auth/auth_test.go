package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

func TestSecretsRedaction(t *testing.T) {
	rawSecret := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload12345"
	redacted := RedactSecret(rawSecret)

	if strings.Contains(redacted, "secretpayload12345") {
		t.Fatalf("redacted secret leaked raw payload: %s", redacted)
	}
	if !strings.HasPrefix(redacted, "eyJh") || !strings.Contains(redacted, "[REDACTED:") {
		t.Errorf("unexpected redacted secret format: %s", redacted)
	}

	shortSecret := "12345"
	if RedactSecret(shortSecret) != "[REDACTED]" {
		t.Errorf("short secret not redacted properly: %s", RedactSecret(shortSecret))
	}

	headers := map[string]string{
		"Authorization": "Bearer supersecrettoken",
		"Cookie":        "session=secret123; user=alice",
		"Content-Type":  "application/json",
	}

	redactedHeaders := RedactHeaders(headers)
	if strings.Contains(redactedHeaders["Authorization"], "supersecrettoken") {
		t.Errorf("Authorization header not redacted: %v", redactedHeaders)
	}
	if strings.Contains(redactedHeaders["Cookie"], "secret123") {
		t.Errorf("Cookie header not redacted: %v", redactedHeaders)
	}
	if redactedHeaders["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should not be redacted: %s", redactedHeaders["Content-Type"])
	}

	cookies := []*http.Cookie{
		{Name: "session", Value: "sessiontoken9999"},
	}
	redactedCookies := RedactCookies(cookies)
	if strings.Contains(redactedCookies[0].Value, "sessiontoken9999") {
		t.Errorf("cookie value not redacted: %v", redactedCookies[0].Value)
	}
}

func TestDetectSessionStatus(t *testing.T) {
	// 1. 401 Unauthorized
	resp401 := &http.Response{StatusCode: http.StatusUnauthorized}
	status, details := DetectSessionStatus(resp401, nil)
	if status != SessionStatusExpired {
		t.Errorf("expected expired for 401, got %s (%s)", status, details)
	}

	// 2. 302 Redirect to /login
	resp302 := &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"https://example.com/auth/login"}},
	}
	status, details = DetectSessionStatus(resp302, nil)
	if status != SessionStatusExpired {
		t.Errorf("expected expired for login redirect, got %s (%s)", status, details)
	}

	// 3. 200 with JSON session expired message
	resp200Err := &http.Response{StatusCode: http.StatusOK}
	status, details = DetectSessionStatus(resp200Err, []byte(`{"error": "session expired", "code": 4010}`))
	if status != SessionStatusExpired {
		t.Errorf("expected expired for body message, got %s (%s)", status, details)
	}

	// 4. 200 OK with normal content
	resp200OK := &http.Response{StatusCode: http.StatusOK}
	status, details = DetectSessionStatus(resp200OK, []byte(`{"id": 42, "name": "Document A"}`))
	if status != SessionStatusValid {
		t.Errorf("expected valid for 200 OK, got %s (%s)", status, details)
	}
}

func TestProfileApplyAndRedactedSummary(t *testing.T) {
	p := NewProfile("user_alice", "tenant_a", "bearer")
	p.SetHeader("Authorization", "Bearer token_alice_12345")
	p.SetHeader("X-Custom-Tenant", "tenant_a")
	p.AddCookie(&http.Cookie{Name: "session_id", Value: "sess_cookie_alice"})

	req, _ := http.NewRequest("GET", "https://api.example.com/me", nil)
	p.ApplyToRequest(req)

	if req.Header.Get("Authorization") != "Bearer token_alice_12345" {
		t.Errorf("Authorization header not applied to request")
	}
	cookie, err := req.Cookie("session_id")
	if err != nil || cookie.Value != "sess_cookie_alice" {
		t.Errorf("Cookie not applied to request")
	}

	summary := p.RedactedSummary()
	if strings.Contains(summary.RedactedHeaders["Authorization"], "token_alice_12345") {
		t.Errorf("RedactedSummary leaked raw token: %v", summary.RedactedHeaders)
	}
	if len(summary.CookieNames) != 1 || summary.CookieNames[0] != "session_id" {
		t.Errorf("unexpected cookie names in summary: %v", summary.CookieNames)
	}
}

func TestProfileValidateSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer valid_token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user": "alice"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	}))
	defer server.Close()

	sc := scope.New([]string{"127.0.0.1", "localhost"}, nil)
	client := httpx.New(httpx.Config{
		Scope:       sc,
		Timeout:     2 * time.Second,
		MaxBodySize: 1024 * 1024,
		GlobalRate:  50,
		PerHostRate: 50,
	})

	// Valid profile
	pValid := NewProfile("user_valid", "tenant_1", "bearer")
	pValid.SetHeader("Authorization", "Bearer valid_token")
	status, _, err := pValid.ValidateSession(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("ValidateSession error: %v", err)
	}
	if status != SessionStatusValid {
		t.Errorf("expected valid session, got %s", status)
	}

	// Expired profile
	pExpired := NewProfile("user_expired", "tenant_1", "bearer")
	pExpired.SetHeader("Authorization", "Bearer expired_token")
	status, _, err = pExpired.ValidateSession(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("ValidateSession error: %v", err)
	}
	if status != SessionStatusExpired {
		t.Errorf("expected expired session, got %s", status)
	}
}

func TestSaveAndLoadProfiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scoutr_auth_test")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "profiles.json")

	p1 := NewProfile("owner", "org_1", "bearer")
	p1.SetHeader("Authorization", "Bearer secret1")

	p2 := NewProfile("tester", "org_2", "cookie")
	p2.AddCookie(&http.Cookie{Name: "session", Value: "sess2"})

	if err := SaveProfiles(filePath, []*Profile{p1, p2}); err != nil {
		t.Fatalf("SaveProfiles failed: %v", err)
	}

	loaded, err := LoadProfiles(filePath)
	if err != nil {
		t.Fatalf("LoadProfiles failed: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 profiles loaded, got %d", len(loaded))
	}
	if loaded[0].PrincipalLabel != "owner" || loaded[0].Headers["Authorization"] != "Bearer secret1" {
		t.Errorf("loaded profile 1 mismatch: %+v", loaded[0])
	}
	if loaded[1].PrincipalLabel != "tester" || len(loaded[1].Cookies) != 1 {
		t.Errorf("loaded profile 2 mismatch: %+v", loaded[1])
	}
}

func TestImportHAR(t *testing.T) {
	harJSON := []byte(`{
		"log": {
			"version": "1.2",
			"entries": [
				{
					"startedDateTime": "2026-11-15T10:00:00Z",
					"request": {
						"method": "GET",
						"url": "https://api.example.com/api/v1/users/42/documents/100",
						"headers": [
							{ "name": "Authorization", "value": "Bearer har_token_abc" },
							{ "name": "Accept", "value": "application/json" }
						],
						"queryString": [
							{ "name": "version", "value": "2" }
						],
						"cookies": [
							{ "name": "auth_cookie", "value": "cookie_val_xyz" }
						]
					},
					"response": {
						"status": 200,
						"headers": [
							{ "name": "Content-Type", "value": "application/json" }
						],
						"content": {
							"size": 50,
							"mimeType": "application/json",
							"text": "{\"doc_id\": 100, \"content\": \"secret\"}"
						}
					}
				},
				{
					"startedDateTime": "2026-11-15T10:01:00Z",
					"request": {
						"method": "GET",
						"url": "https://out-of-scope-cdn.com/analytics.js",
						"headers": []
					},
					"response": { "status": 200 }
				}
			]
		}
	}`)

	sc := scope.New([]string{"api.example.com"}, nil)
	profile := NewProfile("user_har", "tenant_har", "")

	imported, err := ImportHAR(harJSON, sc, profile)
	if err != nil {
		t.Fatalf("ImportHAR failed: %v", err)
	}

	// Out-of-scope CDN entry must be rejected
	if len(imported) != 1 {
		t.Fatalf("expected 1 in-scope imported entry, got %d", len(imported))
	}

	entry := imported[0]
	if entry.URL != "https://api.example.com/api/v1/users/42/documents/100" {
		t.Errorf("unexpected URL: %s", entry.URL)
	}

	// Check evidence has redacted Authorization header
	if strings.Contains(entry.RequestHeaders["Authorization"], "har_token_abc") {
		t.Errorf("evidence leaked raw Authorization header: %v", entry.RequestHeaders)
	}

	// Check target profile captured unredacted credentials in memory
	if profile.Headers["Authorization"] != "Bearer har_token_abc" {
		t.Errorf("target profile failed to extract Authorization header: %v", profile.Headers)
	}
	if len(profile.Cookies) != 1 || profile.Cookies[0].Value != "cookie_val_xyz" {
		t.Errorf("target profile failed to extract cookie: %v", profile.Cookies)
	}

	// Test malformed HAR
	_, err = ImportHAR([]byte(`not valid json`), sc, nil)
	if err == nil {
		t.Errorf("expected error for malformed HAR, got nil")
	}
}

func TestCheckDistinctCredentials(t *testing.T) {
	// Identical Authorization headers
	p1 := NewProfile("alice", "tenant1", "bearer")
	p1.SetHeader("Authorization", "Bearer shared_token_123")

	p2 := NewProfile("bob", "tenant2", "bearer")
	p2.SetHeader("Authorization", "Bearer shared_token_123")

	if err := CheckDistinctCredentials(p1, p2); err == nil {
		t.Errorf("expected error for identical Authorization headers, got nil")
	}

	// Identical Cookie values
	p3 := NewProfile("carol", "tenant1", "cookie")
	p3.AddCookie(&http.Cookie{Name: "session", Value: "cookie_secret_999"})

	p4 := NewProfile("dave", "tenant2", "cookie")
	p4.AddCookie(&http.Cookie{Name: "session", Value: "cookie_secret_999"})

	if err := CheckDistinctCredentials(p3, p4); err == nil {
		t.Errorf("expected error for identical cookie values, got nil")
	}

	// Truly distinct credentials
	p5 := NewProfile("eve", "tenant1", "bearer")
	p5.SetHeader("Authorization", "Bearer token_eve_unique")

	p6 := NewProfile("frank", "tenant2", "bearer")
	p6.SetHeader("Authorization", "Bearer token_frank_unique")

	if err := CheckDistinctCredentials(p5, p6); err != nil {
		t.Errorf("expected distinct credentials to pass, got: %v", err)
	}
}

func TestRedactURLSecrets(t *testing.T) {
	rawURL := "https://api.example.com/v1/data?token=secret12345&user=alice&api_key=abcdef987654&page=2"
	redacted := RedactURLSecrets(rawURL)

	if strings.Contains(redacted, "secret12345") {
		t.Errorf("token leaked in redacted URL: %s", redacted)
	}
	if strings.Contains(redacted, "abcdef987654") {
		t.Errorf("api_key leaked in redacted URL: %s", redacted)
	}
	if !strings.Contains(redacted, "user=alice") {
		t.Errorf("user param dropped from URL: %s", redacted)
	}
	if !strings.Contains(redacted, "page=2") {
		t.Errorf("page param dropped from URL: %s", redacted)
	}
}

func TestRedactJSONSecrets(t *testing.T) {
	rawJSON := []byte(`{
		"username": "alice",
		"token": "super_secret_token_123",
		"nested": {
			"password": "my_password_xyz",
			"score": 100
		}
	}`)

	redacted := RedactJSONSecrets(rawJSON)
	redactedStr := string(redacted)

	if strings.Contains(redactedStr, "super_secret_token_123") {
		t.Errorf("token leaked in redacted JSON: %s", redactedStr)
	}
	if strings.Contains(redactedStr, "my_password_xyz") {
		t.Errorf("password leaked in redacted JSON: %s", redactedStr)
	}
	if !strings.Contains(redactedStr, "alice") || !strings.Contains(redactedStr, "100") {
		t.Errorf("non-sensitive values missing: %s", redactedStr)
	}
}

func TestHARImportHardening(t *testing.T) {
	sc := scope.New([]string{"api.example.com"}, nil)

	// 1. Oversized HAR test (> 10MB)
	oversized := make([]byte, MaxHARSizeBytes+1024)
	_, err := ImportHAR(oversized, sc, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Errorf("expected size limit error for oversized HAR, got: %v", err)
	}

	// 2. Query parameter secrets in HAR URLs are redacted
	harWithSecrets := []byte(`{
		"log": {
			"version": "1.2",
			"entries": [
				{
					"startedDateTime": "2026-11-15T10:00:00Z",
					"request": {
						"method": "GET",
						"url": "https://api.example.com/v1/profile?token=har_secret_token_val&format=json",
						"headers": [],
						"queryString": [
							{"name": "token", "value": "har_secret_token_val"},
							{"name": "format", "value": "json"}
						]
					},
					"response": {
						"status": 200,
						"headers": [],
						"content": {
							"mimeType": "application/json",
							"text": "{\"user\": \"har_user\", \"secret\": \"leaked_response_secret\"}"
						}
					}
				}
			]
		}
	}`)

	imported, err := ImportHAR(harWithSecrets, sc, nil)
	if err != nil {
		t.Fatalf("ImportHAR failed: %v", err)
	}
	if len(imported) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(imported))
	}

	// URL query secrets must be redacted
	if strings.Contains(imported[0].URL, "har_secret_token_val") {
		t.Errorf("URL query secret was not redacted: %s", imported[0].URL)
	}
	// Response body secrets must be redacted
	if strings.Contains(imported[0].ResponseBody, "leaked_response_secret") {
		t.Errorf("Response body secret was not redacted: %s", imported[0].ResponseBody)
	}
}

func TestProfileInstanceAndRoleIsolation(t *testing.T) {
	p := NewProfile("alice", "tenant_alpha", "bearer")
	p.SetInstance("cluster-us-east-1")
	p.SetRole("admin")
	p.AddCookie(&http.Cookie{Name: "session", Value: "session_val_123"})

	if p.InstanceLabel != "cluster-us-east-1" {
		t.Errorf("unexpected instance label: %s", p.InstanceLabel)
	}
	if p.RoleLabel != "admin" {
		t.Errorf("unexpected role label: %s", p.RoleLabel)
	}

	summary := p.RedactedSummary()
	if summary.InstanceLabel != "cluster-us-east-1" {
		t.Errorf("summary missing instance label: %s", summary.InstanceLabel)
	}
	if summary.RoleLabel != "admin" {
		t.Errorf("summary missing role label: %s", summary.RoleLabel)
	}

	// Cookie deep copy isolation: modifying request cookies does not alter profile cookies
	req, _ := http.NewRequest("GET", "https://api.example.com/test", nil)
	p.ApplyToRequest(req)

	reqCookie, err := req.Cookie("session")
	if err != nil {
		t.Fatalf("cookie not attached: %v", err)
	}
	reqCookie.Value = "tampered_value"

	if p.Cookies[0].Value != "session_val_123" {
		t.Errorf("cookie bled/mutated back into profile! got: %s", p.Cookies[0].Value)
	}
}

func TestProfileIdentityVerification(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch auth {
		case "Bearer token_alice":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "user_42", "tenant_id": "tenant_1", "role": "admin"}`))
		case "Bearer token_bob":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "user_99", "tenant_id": "tenant_1", "role": "member"}`))
		case "Bearer token_impostor":
			// Different token, but resolves to the exact same underlying user ID!
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "user_42", "tenant_id": "tenant_1", "role": "admin"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	sc := scope.New([]string{"127.0.0.1", "localhost"}, nil)
	client := httpx.New(httpx.Config{
		Scope:       sc,
		Timeout:     2 * time.Second,
		MaxBodySize: 1024 * 1024,
		GlobalRate:  50,
		PerHostRate: 50,
	})

	// 1. Verify Alice
	alice := NewProfile("alice", "tenant_1", "bearer")
	alice.SetHeader("Authorization", "Bearer token_alice")
	alice.SetIdentityEndpoint(server.URL + "/api/v1/me")

	if err := alice.VerifyIdentity(context.Background(), client); err != nil {
		t.Fatalf("verify alice failed: %v", err)
	}
	if alice.VerifiedID != "user_42" || alice.IdentityStatus != "verified" || alice.VerifiedRole != "admin" {
		t.Errorf("unexpected alice identity: %+v", alice)
	}

	// 2. Verify Bob
	bob := NewProfile("bob", "tenant_1", "bearer")
	bob.SetHeader("Authorization", "Bearer token_bob")
	bob.SetIdentityEndpoint(server.URL + "/api/v1/me")

	if err := bob.VerifyIdentity(context.Background(), client); err != nil {
		t.Fatalf("verify bob failed: %v", err)
	}
	if bob.VerifiedID != "user_99" || bob.IdentityStatus != "verified" {
		t.Errorf("unexpected bob identity: %+v", bob)
	}

	// Distinct verified users should pass isolation check
	if err := CheckDistinctCredentials(alice, bob); err != nil {
		t.Errorf("expected distinct users to pass, got: %v", err)
	}

	// 3. Verify Impostor (different token, same verified ID user_42)
	impostor := NewProfile("impostor", "tenant_1", "bearer")
	impostor.SetHeader("Authorization", "Bearer token_impostor")
	impostor.SetIdentityEndpoint(server.URL + "/api/v1/me")

	if err := impostor.VerifyIdentity(context.Background(), client); err != nil {
		t.Fatalf("verify impostor failed: %v", err)
	}
	if impostor.VerifiedID != "user_42" {
		t.Errorf("expected impostor to resolve to user_42, got: %s", impostor.VerifiedID)
	}

	// Different tokens but identical verified user ID must FAIL CheckDistinctCredentials
	if err := CheckDistinctCredentials(alice, impostor); err == nil || !strings.Contains(err.Error(), "same verified user ID") {
		t.Errorf("expected error blocking same verified user identity masquerade, got: %v", err)
	}

	// 4. Failed identity endpoint
	invalid := NewProfile("invalid", "tenant_1", "bearer")
	invalid.SetHeader("Authorization", "Bearer token_invalid")
	invalid.SetIdentityEndpoint(server.URL + "/api/v1/me")

	if err := invalid.VerifyIdentity(context.Background(), client); err == nil {
		t.Errorf("expected error for unauthorized identity endpoint, got nil")
	}
	if invalid.IdentityStatus != "failed" {
		t.Errorf("expected status failed, got: %s", invalid.IdentityStatus)
	}

	// 5. Unconfigured identity endpoint returns nil and status unverified
	unconfigured := NewProfile("unconfigured", "tenant_1", "bearer")
	if err := unconfigured.VerifyIdentity(context.Background(), client); err != nil {
		t.Errorf("expected nil for empty endpoint, got: %v", err)
	}
	if unconfigured.IdentityStatus != "unverified" {
		t.Errorf("expected unverified, got: %s", unconfigured.IdentityStatus)
	}

	// 6. Nil client returns error
	unconfigured.SetIdentityEndpoint("http://localhost/test")
	if err := unconfigured.VerifyIdentity(context.Background(), nil); err == nil {
		t.Errorf("expected error for nil client, got nil")
	}

	// 7. SetVerifiedIdentity manual helper
	manual := NewProfile("manual", "tenant_manual", "bearer")
	manual.SetVerifiedIdentity("user_manual_1", "tenant_manual", "admin")
	if manual.VerifiedID != "user_manual_1" || manual.IdentityStatus != "verified" || manual.VerifiedRole != "admin" {
		t.Errorf("unexpected manual verified identity: %+v", manual)
	}

	// 8. Edge cases for CheckDistinctCredentials and Profile
	if err := CheckDistinctCredentials(nil, manual); err == nil {
		t.Errorf("expected error for nil profile")
	}
	twinPrincipal := NewProfile("manual", "other_tenant", "bearer")
	if err := CheckDistinctCredentials(manual, twinPrincipal); err == nil {
		t.Errorf("expected error for identical principal labels")
	}

	manual.AddCookie(nil)
	manual.ApplyToRequest(nil)
}

func TestSaveAndLoadProfilesAtomicAndCorrupt(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFile := filepath.Join(tmpDir, "auth_secrets.json")

	p1 := NewProfile("alice", "tenant_1", "bearer")
	p1.SetHeader("Authorization", "Bearer secret_token_123")
	p1.AddCookie(&http.Cookie{Name: "session", Value: "sess_xyz"})

	p2 := NewProfile("bob", "tenant_2", "bearer")
	p2.SetHeader("Authorization", "Bearer secret_token_456")

	// 1. SaveProfiles atomically writes
	if err := SaveProfiles(secretsFile, []*Profile{p1, p2}); err != nil {
		t.Fatalf("SaveProfiles failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(secretsFile); err != nil {
		t.Fatalf("expected secret file to exist: %v", err)
	}

	// 2. LoadProfiles successfully loads
	loaded, err := LoadProfiles(secretsFile)
	if err != nil {
		t.Fatalf("LoadProfiles failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(loaded))
	}
	if loaded[0].Headers["Authorization"] != "Bearer secret_token_123" {
		t.Errorf("expected secret loaded correctly")
	}

	// 3. Empty file returns empty slice, no error
	emptyFile := filepath.Join(tmpDir, "empty_secrets.json")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyLoaded, err := LoadProfiles(emptyFile)
	if err != nil {
		t.Fatalf("LoadProfiles on empty file should succeed, got: %v", err)
	}
	if len(emptyLoaded) != 0 {
		t.Errorf("expected 0 profiles from empty file, got: %d", len(emptyLoaded))
	}

	// 4. Corrupted file returns informative error
	corruptFile := filepath.Join(tmpDir, "corrupt_secrets.json")
	if err := os.WriteFile(corruptFile, []byte("{broken_json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadProfiles(corruptFile)
	if err == nil {
		t.Errorf("expected error when loading corrupt JSON profiles")
	}
}
