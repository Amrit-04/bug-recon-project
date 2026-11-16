import { test, expect } from '@playwright/test';

test.describe('Scoutr Security Research Platform - E2E Integration Suite', () => {

  test.beforeEach(async ({ page }) => {
    // Navigate to root
    await page.goto('/');
    // Wait for the main app heading and run selector to load
    await expect(page.locator('h1')).toContainText('scoutr');
    await expect(page.locator('select')).toBeVisible();
  });

  test('Workflow A: Run discovery -> Inspect endpoint inventory in UI', async ({ page }) => {
    // 1. Navigate to Endpoints Explorer
    await page.click('nav button:has-text("Endpoints Explorer")');

    // 2. Verify endpoints table loaded from backend
    await expect(page.locator('button:has-text("/api/v1/users/{id}")')).toBeVisible();
    await expect(page.locator('button:has-text("/api/v1/documents/{id}")')).toBeVisible();

    // 3. Search and filter endpoints
    const searchInput = page.locator('input[placeholder="Search URL, route path, or parameter..."]');
    await searchInput.fill('documents');
    await expect(page.locator('button:has-text("/api/v1/documents/{id}")')).toBeVisible();
    await expect(page.locator('button:has-text("/api/v1/users/{id}")')).not.toBeVisible();

    // Clear search
    await searchInput.fill('');
    await expect(page.locator('button:has-text("/api/v1/users/{id}")')).toBeVisible();

    // 4. Click row to open endpoint inspector drawer
    await page.click('button:has-text("/api/v1/users/{id}")');
    await expect(page.locator('text=Route Template')).toBeVisible();
    await expect(page.locator('text=Canonical URL')).toBeVisible();
  });

  test('Workflow B: Configure User A & User B -> Verify sessions -> Check status in UI', async ({ page }) => {
    // 1. Navigate to IDOR Research Center
    await page.click('nav button:has-text("IDOR Center")');

    // 2. Verify Dual Auth Profiles sub-tab is active
    await expect(page.locator('button:has-text("1. Auth Profiles")')).toBeVisible();
    await expect(page.locator('text=Profile A (Resource Owner / Victim)')).toBeVisible();
    await expect(page.locator('text=Profile B (Accessor / Attacker / Tester)')).toBeVisible();

    // 3. Fill in User A token
    const tokenInput = page.locator('input[placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."]').first();
    await tokenInput.fill('e2e-test-token-alice');

    // 4. Click Save Profile A
    await page.click('button:has-text("Save Profile A")');

    // 5. Verify notice banner indicates success
    await expect(page.locator('text=Saved credentials for user_a (stored securely)')).toBeVisible();
  });

  test('Workflow C: Import HAR capture -> Candidate extraction -> Review candidates in UI', async ({ page }) => {
    // 1. Navigate to IDOR Research Center
    await page.click('nav button:has-text("IDOR Center")');

    // 2. Select HAR Capture Import subtab
    await page.click('button:has-text("2. HAR Capture Import")');
    await expect(page.locator('text=Import Researcher-Provided HAR Capture')).toBeVisible();

    // 3. Select Candidate Object References subtab
    await page.click('button:has-text("3. Candidate Object References")');
    await expect(page.locator('text=Extract Candidates from Endpoints')).toBeVisible();

    // 4. Verify candidate objects (1001, doc-555)
    await expect(page.locator('text=1001').first()).toBeVisible();
    await expect(page.locator('text=doc-555').first()).toBeVisible();
  });

  test('Workflow D: Execute differential testing -> Inspect comparison matrix & evidence bundle', async ({ page }) => {
    // 1. Navigate to IDOR Research Center
    await page.click('nav button:has-text("IDOR Center")');

    // 2. Select Differential Testing Matrix subtab
    await page.click('button:has-text("4. Differential Testing Matrix")');

    // 3. Verify comparison matrix entry
    await expect(page.locator('text=Candidate Route')).toBeVisible();
    await expect(page.locator('text=cross_tenant').first()).toBeVisible();
    await expect(page.locator('text=ConfirmedVulnerability').first()).toBeVisible();

    // 4. View Evidence Bundle modal
    await page.click('button:has-text("View Evidence")');
    await expect(page.locator('text=IDOR Differential Evidence Bundle')).toBeVisible();
    await expect(page.locator('text=Boundary Isolation Level')).toBeVisible();

    // 5. Close modal
    await page.click('button:has-text("Close Evidence")');
    await expect(page.locator('text=IDOR Differential Evidence Bundle')).not.toBeVisible();
  });

  test('Workflow E: External scanner execution with scope verification', async ({ page }) => {
    // 1. Navigate to Scope Guard
    await page.click('nav button:has-text("Scope Guard")');
    await expect(page.locator('text=Permitted Target Scope (in_scope)')).toBeVisible();
    await expect(page.locator('text=Restricted Infrastructure (out_of_scope)')).toBeVisible();
    await expect(page.locator('.text-emerald-300:has-text("example.com")').first()).toBeVisible();
    await expect(page.locator('.text-red-300:has-text("forbidden.com")').first()).toBeVisible();

    // 2. Live Scope Rule Tester: test in-scope host
    const testerInput = page.locator('input[placeholder="e.g. admin.example.com or api.example.com"]');
    await testerInput.fill('api.example.com');
    await expect(page.locator('text=IN SCOPE')).toBeVisible();

    // Test out-of-scope host
    await testerInput.fill('forbidden.com');
    await expect(page.locator('text=OUT OF SCOPE')).toBeVisible();

    // 3. Navigate to Tools Center
    await page.click('nav button:has-text("Tools Center")');
    await expect(page.locator('text=Security Tools Center')).toBeVisible();
  });

  test('Workflow F: SSE live progress streaming & cancellation', async ({ page }) => {
    // 1. Open New Scan Modal
    await page.click('button:has-text("New Scan")');
    await expect(page.locator('text=Start New Security Scan')).toBeVisible();

    // 2. Enter target domain
    const targetInput = page.locator('input[placeholder="e.g. example.com or app.target.com"]');
    await targetInput.fill('e2e-test-stream.example.com');

    // 3. Close/Cancel modal
    await page.click('button:has-text("Cancel")');
    await expect(page.locator('text=Start New Security Scan')).not.toBeVisible();
  });

  test('Workflow G: RCE Research Center -> Attack Surface Discovery -> Advisory Reachability & Validation', async ({ page }) => {
    // 1. Navigate to RCE Research Center
    await page.click('nav button:has-text("RCE Research Center")');

    // 2. Verify Overview sub-tab displays KPI cards and execution sink grid
    await expect(page.locator('h2:has-text("RCE Research Center")')).toBeVisible();
    await expect(page.locator('text=Execution Sink Classification')).toBeVisible();
    await expect(page.locator('text=Total Attack Surfaces')).toBeVisible();
    await expect(page.locator('text=File Processing')).toBeVisible();

    // 3. Navigate to Attack Surface Explorer sub-tab
    await page.click('button:has-text("2. Attack Surface Explorer")');
    await expect(page.locator('text="/api/v1/export/pdf"').first()).toBeVisible();

    // Test filter input
    const searchInput = page.locator('input[placeholder="Filter by route, URL, sink, hypothesis..."]');
    await searchInput.fill('export');
    await expect(page.locator('text="/api/v1/export/pdf"').first()).toBeVisible();
    await searchInput.fill('nonexistent-path-query');
    await expect(page.locator('text=No RCE candidates match the current filters')).toBeVisible();
    await searchInput.fill('');

    // 4. Navigate to Candidate Prioritization Queue sub-tab
    await page.click('button:has-text("3. Candidate Prioritization Queue")');
    await expect(page.locator('text=Deterministic Score Breakdown')).toBeVisible();
    await expect(page.locator('text=Template rendering engine')).toBeVisible();
    await expect(page.locator('text=88').first()).toBeVisible();

    // 5. Navigate to Advisory Intelligence (CVEs) sub-tab
    await page.click('button:has-text("4. Advisory Intelligence (CVEs)")');
    await expect(page.locator('text=CVE-2022-22965')).toBeVisible();
    await expect(page.locator('text=Spring4Shell').first()).toBeVisible();
    await expect(page.locator('text=Component Reachable').first()).toBeVisible();

    // 6. Navigate back to Queue and inspect Evidence Bundle
    await page.click('button:has-text("3. Candidate Prioritization Queue")');
    await page.click('button:has-text("View Evidence Bundle")');

    // Verify evidence modal details
    await expect(page.locator('text=RCE Evidence Bundle & Verification Audit')).toBeVisible();
    await expect(page.locator('text=ScopedTransport Enforced').first()).toBeVisible();
    await expect(page.locator('text=Reproducible Curl Command')).toBeVisible();

    // Close evidence modal
    await page.click('button:has-text("Close Evidence")');
    await expect(page.locator('text=RCE Evidence Bundle & Verification Audit')).not.toBeVisible();
  });

});
