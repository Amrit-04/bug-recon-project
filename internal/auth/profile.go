package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/httpx"
)

// Profile represents an authenticated research account profile.
// Raw credentials (Headers and Cookies) are strictly isolated and never leaked into ordinary artifacts or prompts.
type Profile struct {
	// Researcher-defined labels
	PrincipalLabel string `json:"principal_label"`          // e.g. "user_a", "owner", "alice"
	TenantLabel    string `json:"tenant_label"`             // e.g. "tenant_1", "org_alpha"
	InstanceLabel  string `json:"instance_label,omitempty"` // e.g. "prod-us-1", "shard-b", "instance-alpha"
	RoleLabel      string `json:"role_label,omitempty"`     // e.g. "admin", "member", "viewer"
	AuthType       string `json:"auth_type"`                // "bearer", "cookie", "custom"

	// Authenticated credentials
	Headers map[string]string `json:"headers,omitempty"` // e.g. "Authorization": "Bearer ..."
	Cookies []*http.Cookie    `json:"cookies,omitempty"`

	// Validation and identity state
	Status           SessionStatus `json:"status"`
	StatusDetails    string        `json:"status_details,omitempty"`
	IdentityEndpoint string        `json:"identity_endpoint,omitempty"` // URL to query for identity verification (e.g. /api/me)
	IdentityStatus   string        `json:"identity_status,omitempty"`   // "unverified", "verified", "failed"
	VerifiedID       string        `json:"verified_id,omitempty"`       // Distinct user ID returned by identity endpoint
	VerifiedTenant   string        `json:"verified_tenant,omitempty"`   // Tenant ID confirmed by identity endpoint
	VerifiedRole     string        `json:"verified_role,omitempty"`     // Role confirmed by identity endpoint
	LastValidated    time.Time     `json:"last_validated,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
}

// ProfileSummary is a safe, redacted representation suitable for reports, logs, and LLM prompts.
type ProfileSummary struct {
	PrincipalLabel   string            `json:"principal_label"`
	TenantLabel      string            `json:"tenant_label"`
	InstanceLabel    string            `json:"instance_label,omitempty"`
	RoleLabel        string            `json:"role_label,omitempty"`
	AuthType         string            `json:"auth_type"`
	IdentityEndpoint string            `json:"identity_endpoint,omitempty"`
	IdentityStatus   string            `json:"identity_status,omitempty"`
	VerifiedID       string            `json:"verified_id,omitempty"`
	RedactedHeaders  map[string]string `json:"headers,omitempty"`
	CookieNames      []string          `json:"cookie_names,omitempty"`
	Status           SessionStatus     `json:"status"`
	LastValidated    time.Time         `json:"last_validated,omitempty"`
}

// NewProfile creates an initialized authentication profile with clean labels.
func NewProfile(principal, tenant, authType string) *Profile {
	return &Profile{
		PrincipalLabel: strings.TrimSpace(principal),
		TenantLabel:    strings.TrimSpace(tenant),
		InstanceLabel:  "default",
		RoleLabel:      "member",
		AuthType:       strings.ToLower(strings.TrimSpace(authType)),
		IdentityStatus: "unverified",
		Headers:        make(map[string]string),
		Status:         SessionStatusUnknown,
		CreatedAt:      time.Now(),
	}
}

// SetIdentityEndpoint configures an endpoint for authenticated identity verification.
func (p *Profile) SetIdentityEndpoint(endpoint string) {
	p.IdentityEndpoint = strings.TrimSpace(endpoint)
}

// SetVerifiedIdentity manually sets verified identity attributes (e.g. from controlled HAR or test fixtures).
func (p *Profile) SetVerifiedIdentity(id, tenant, role string) {
	p.VerifiedID = strings.TrimSpace(id)
	if tenant != "" {
		p.VerifiedTenant = strings.TrimSpace(tenant)
	}
	if role != "" {
		p.VerifiedRole = strings.TrimSpace(role)
	}
	p.IdentityStatus = "verified"
}

// SetInstance assigns an explicit deployment or cluster instance label.
func (p *Profile) SetInstance(instance string) {
	p.InstanceLabel = strings.TrimSpace(instance)
}

// SetRole assigns an explicit user role label within the tenant.
func (p *Profile) SetRole(role string) {
	p.RoleLabel = strings.TrimSpace(role)
}

// SetHeader sets an HTTP header on the profile.
func (p *Profile) SetHeader(key, value string) {
	if p.Headers == nil {
		p.Headers = make(map[string]string)
	}
	p.Headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
}

// AddCookie appends a cookie to the profile.
func (p *Profile) AddCookie(c *http.Cookie) {
	if c == nil {
		return
	}
	// Store clone to prevent external modification
	clone := *c
	p.Cookies = append(p.Cookies, &clone)
}

// ApplyToRequest attaches this profile's credentials (headers and cookies) to an outgoing HTTP request.
// It creates fresh copies to guarantee that credentials and cookies cannot bleed across sessions.
func (p *Profile) ApplyToRequest(req *http.Request) {
	if req == nil {
		return
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range p.Cookies {
		// Deep clone cookie before attaching
		clone := *c
		req.AddCookie(&clone)
	}
}

// RedactedSummary generates a safe copy with all credentials masked.
func (p *Profile) RedactedSummary() ProfileSummary {
	var cookieNames []string
	for _, c := range p.Cookies {
		cookieNames = append(cookieNames, c.Name)
	}

	return ProfileSummary{
		PrincipalLabel:   p.PrincipalLabel,
		TenantLabel:      p.TenantLabel,
		InstanceLabel:    p.InstanceLabel,
		RoleLabel:        p.RoleLabel,
		AuthType:         p.AuthType,
		IdentityEndpoint: p.IdentityEndpoint,
		IdentityStatus:   p.IdentityStatus,
		VerifiedID:       p.VerifiedID,
		RedactedHeaders:  RedactHeaders(p.Headers),
		CookieNames:      cookieNames,
		Status:           p.Status,
		LastValidated:    p.LastValidated,
	}
}

// VerifyIdentity queries the configured IdentityEndpoint using the profile's authenticated credentials
// to verify the actual principal identity (user ID, tenant, role).
func (p *Profile) VerifyIdentity(ctx context.Context, client *httpx.Client) error {
	if p.IdentityEndpoint == "" {
		p.IdentityStatus = "unverified"
		return nil
	}
	if client == nil {
		return fmt.Errorf("httpx client required for identity verification")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.IdentityEndpoint, nil)
	if err != nil {
		p.IdentityStatus = "failed"
		return fmt.Errorf("create identity request: %w", err)
	}

	p.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		p.IdentityStatus = "failed"
		return fmt.Errorf("execute identity request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.IdentityStatus = "failed"
		return fmt.Errorf("identity endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		p.IdentityStatus = "failed"
		return fmt.Errorf("read identity response: %w", err)
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		p.IdentityStatus = "failed"
		return fmt.Errorf("parse identity JSON: %w", err)
	}

	// Extract verified user/principal ID
	for _, key := range []string{"id", "user_id", "sub", "userId", "username", "email"} {
		if val, exists := data[key]; exists && val != nil {
			p.VerifiedID = fmt.Sprintf("%v", val)
			break
		}
	}

	// Extract verified tenant ID
	for _, key := range []string{"tenant_id", "tenantId", "org_id", "orgId", "organization_id", "account_id"} {
		if val, exists := data[key]; exists && val != nil {
			p.VerifiedTenant = fmt.Sprintf("%v", val)
			break
		}
	}

	// Extract verified role
	for _, key := range []string{"role", "role_name", "user_role", "permission_level"} {
		if val, exists := data[key]; exists && val != nil {
			p.VerifiedRole = fmt.Sprintf("%v", val)
			break
		}
	}

	if p.VerifiedID == "" {
		p.IdentityStatus = "failed"
		return fmt.Errorf("no user identifier found in identity endpoint response")
	}

	p.IdentityStatus = "verified"
	return nil
}

// CheckDistinctCredentials verifies that two profiles are truly independent and not sharing identical credentials.
func CheckDistinctCredentials(p1, p2 *Profile) error {
	if p1 == nil || p2 == nil {
		return fmt.Errorf("both profiles must be provided")
	}

	if p1.PrincipalLabel == p2.PrincipalLabel {
		return fmt.Errorf("profiles have identical principal label '%s'; two distinct accounts are required", p1.PrincipalLabel)
	}

	// Check verified identities if both profiles have been verified
	if p1.IdentityStatus == "verified" && p2.IdentityStatus == "verified" {
		if p1.VerifiedID != "" && p1.VerifiedID == p2.VerifiedID {
			return fmt.Errorf("credential isolation check failed: profiles '%s' and '%s' resolve to the same verified user ID '%s'; differential testing requires two distinct users",
				p1.PrincipalLabel, p2.PrincipalLabel, p1.VerifiedID)
		}
	}

	// Compare Authorization header
	auth1 := p1.Headers["Authorization"]
	auth2 := p2.Headers["Authorization"]
	if auth1 != "" && auth2 != "" && auth1 == auth2 {
		return fmt.Errorf("profiles '%s' and '%s' have identical Authorization headers; credentials cannot masquerade as separate accounts",
			p1.PrincipalLabel, p2.PrincipalLabel)
	}

	// Compare Api Key
	key1 := p1.Headers["X-Api-Key"]
	key2 := p2.Headers["X-Api-Key"]
	if key1 != "" && key2 != "" && key1 == key2 {
		return fmt.Errorf("profiles '%s' and '%s' have identical X-Api-Key headers", p1.PrincipalLabel, p2.PrincipalLabel)
	}

	// Compare Session Cookie values
	for _, c1 := range p1.Cookies {
		if c1.Value == "" {
			continue
		}
		for _, c2 := range p2.Cookies {
			if c1.Name == c2.Name && c1.Value == c2.Value {
				return fmt.Errorf("profiles '%s' and '%s' share identical cookie '%s'; separate session cookies required",
					p1.PrincipalLabel, p2.PrincipalLabel, c1.Name)
			}
		}
	}

	return nil
}

// ValidateSession tests this profile's credentials against an in-scope validation endpoint using the scope-enforcing client.
func (p *Profile) ValidateSession(ctx context.Context, client *httpx.Client, validationURL string) (SessionStatus, string, error) {
	if client == nil {
		return SessionStatusUnknown, "", fmt.Errorf("httpx client required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validationURL, nil)
	if err != nil {
		return SessionStatusUnknown, "", fmt.Errorf("create validation request: %w", err)
	}

	p.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		p.Status = SessionStatusUnknown
		p.StatusDetails = fmt.Sprintf("validation request failed: %v", err)
		return p.Status, p.StatusDetails, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	status, details := DetectSessionStatus(resp, body)

	p.Status = status
	p.StatusDetails = details
	p.LastValidated = time.Now()

	return status, details, nil
}

// SaveProfiles securely and atomically writes auth profiles to a dedicated file with restricted permissions.
// On POSIX platforms, 0600 mode is enforced; on Windows, ACLs are restricted to the current user.
func SaveProfiles(filePath string, profiles []*Profile) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create auth profile directory: %w", err)
	}

	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth profiles: %w", err)
	}

	// Atomic write: write to temp file in same directory, restrict access, sync, then rename
	tmpFile, err := os.CreateTemp(dir, ".auth-secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp secret file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		// Clean up tmpPath if it still exists (on failure)
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write secret data: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync secret file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close secret file: %w", err)
	}

	// Apply OS-specific strict access control
	_ = RestrictFileAccess(tmpPath)

	// Atomic replacement: on Windows os.Rename fails if target exists, so remove existing first
	_ = os.Remove(filePath)
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("atomic rename secret file: %w", err)
	}

	_ = RestrictFileAccess(filePath)
	return nil
}

// LoadProfiles reads auth profiles from a file with graceful handling of empty or corrupt states.
func LoadProfiles(filePath string) ([]*Profile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read auth profiles: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []*Profile{}, nil
	}

	var profiles []*Profile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("unmarshal auth profiles: %w", err)
	}

	return profiles, nil
}
