import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function setupTestData(baseDir) {
  const runsDir = path.join(baseDir, 'test-runs');
  const runId = 'example.com-20261116-120000';
  const runDir = path.join(runsDir, runId);
  fs.mkdirSync(runDir, { recursive: true });

  // 1. scope.yaml
  const scopeYaml = `in_scope:
  - "example.com"
  - "*.example.com"
out_of_scope:
  - "forbidden.com"
  - "admin.example.com"
`;
  const scopePath = path.join(runsDir, 'scope.yaml');
  fs.writeFileSync(scopePath, scopeYaml, 'utf8');

  // 2. inventory.json
  fs.writeFileSync(
    path.join(runDir, 'inventory.json'),
    JSON.stringify(['api.example.com', 'app.example.com'], null, 2),
    'utf8'
  );

  // 3. ports.json
  fs.writeFileSync(
    path.join(runDir, 'ports.json'),
    JSON.stringify([{ host: 'api.example.com', port: 443, service: 'https', state: 'open' }], null, 2),
    'utf8'
  );

  // 4. httpx.json
  fs.writeFileSync(
    path.join(runDir, 'httpx.json'),
    JSON.stringify([{ url: 'https://api.example.com', status_code: 200, title: 'API Gateway', technologies: ['express', 'node.js'] }], null, 2),
    'utf8'
  );

  // 5. endpoints.json (must be flat array)
  const endpoints = [
    {
      url: 'https://api.example.com/api/v1/users/1001',
      origin: 'https://api.example.com',
      methods: ['GET'],
      normalized_route: '/api/v1/users/{id}',
      tech_fingerprints: ['express'],
      query_params: ['fields'],
      body_fields: [],
      classifications: [{ category: 'identity_access', priority: 1 }],
      auth_observations: [{ status: 'authenticated', principal_label: 'user_a', tenant_label: 'tenant_1' }],
      discovery_sources: ['katana']
    },
    {
      url: 'https://api.example.com/api/v1/documents/doc-555',
      origin: 'https://api.example.com',
      methods: ['GET', 'PUT'],
      normalized_route: '/api/v1/documents/{id}',
      tech_fingerprints: ['express'],
      query_params: ['version'],
      body_fields: ['title', 'content'],
      classifications: [{ category: 'document_management', priority: 2 }],
      auth_observations: [{ status: 'authenticated', principal_label: 'user_a', tenant_label: 'tenant_1' }],
      discovery_sources: ['katana']
    }
  ];
  fs.writeFileSync(path.join(runDir, 'endpoints.json'), JSON.stringify(endpoints, null, 2), 'utf8');

  // 6. auth profiles
  const profiles = [
    {
      principal_label: 'user_a',
      tenant_label: 'tenant_1',
      instance_label: 'us-east',
      role: 'member',
      auth_type: 'bearer',
      identity_status: 'verified',
      verified_id: 'usr_1001',
      identity_endpoint: 'https://api.example.com/api/v1/me',
      cookies: [],
      headers: { Authorization: 'Bearer token-user-a' },
      last_verified_at: new Date().toISOString()
    },
    {
      principal_label: 'user_b',
      tenant_label: 'tenant_2',
      instance_label: 'us-east',
      role: 'member',
      auth_type: 'bearer',
      identity_status: 'verified',
      verified_id: 'usr_1002',
      identity_endpoint: 'https://api.example.com/api/v1/me',
      cookies: [],
      headers: { Authorization: 'Bearer token-user-b' },
      last_verified_at: new Date().toISOString()
    }
  ];
  fs.writeFileSync(path.join(runDir, 'auth_profiles.json'), JSON.stringify(profiles, null, 2), 'utf8');
  fs.writeFileSync(path.join(runDir, 'auth_secrets.json'), JSON.stringify(profiles, null, 2), 'utf8');

  // 7. idor_candidates.json (must be flat array)
  const candidates = [
    {
      id: 'cand-1',
      object_id: '1001',
      location: 'path',
      param_name: 'id',
      route_template: '/api/v1/users/{id}',
      target_url: 'https://api.example.com/api/v1/users/1001',
      method: 'GET',
      owner_principal: 'user_a',
      owner_tenant: 'tenant_1',
      access_policy: 'private'
    },
    {
      id: 'cand-2',
      object_id: 'doc-555',
      location: 'path',
      param_name: 'id',
      route_template: '/api/v1/documents/{id}',
      target_url: 'https://api.example.com/api/v1/documents/doc-555',
      method: 'GET',
      owner_principal: 'user_a',
      owner_tenant: 'tenant_1',
      access_policy: 'private'
    }
  ];
  fs.writeFileSync(path.join(runDir, 'idor_candidates.json'), JSON.stringify(candidates, null, 2), 'utf8');

  // 8. idor_comparisons.json (must be flat array)
  const comparisons = [
    {
      id: 'comp-1',
      candidate: candidates[0],
      owner_profile: {
        principal_label: 'user_a',
        tenant_label: 'tenant_1',
        instance_label: 'us-east',
        role: 'member',
        identity_status: 'verified',
        verified_id: 'usr_1001'
      },
      tester_profile: {
        principal_label: 'user_b',
        tenant_label: 'tenant_2',
        instance_label: 'us-east',
        role: 'member',
        identity_status: 'verified',
        verified_id: 'usr_1002'
      },
      boundary: 'cross_tenant',
      request_url: 'https://api.example.com/api/v1/users/1001',
      method: 'GET',
      owner_status: 200,
      owner_body_size: 128,
      tester_status: 200,
      tester_body_size: 128,
      anon_status: 401,
      status: 'ConfirmedVulnerability',
      is_disclosed: true,
      body_similarity: 0.98,
      evidence_notes: 'Object 1001 disclosed across tenant boundary',
      redacted_owner_response: '{"user_id":"1001","name":"Alice","email":"alice@tenant1.local"}',
      redacted_tester_response: '{"user_id":"1001","name":"Alice","email":"alice@tenant1.local"}',
      timestamp: new Date().toISOString()
    }
  ];
  fs.writeFileSync(path.join(runDir, 'idor_comparisons.json'), JSON.stringify(comparisons, null, 2), 'utf8');

  // 9. validated_findings.json
  const findings = [
    {
      finding: {
        id: 'FINDING-IDOR-1',
        title: 'Cross-Tenant IDOR on /api/v1/users/{id}',
        target: 'https://api.example.com/api/v1/users/1001',
        severity: 'high',
        confidence: 'high',
        cwe: 'CWE-639',
        cvss: 7.5
      },
      status: 'Verified',
      gate_results: [
        { gate_id: 1, name: 'ScopeCheck', passed: true },
        { gate_id: 2, name: 'TargetAlive', passed: true },
        { gate_id: 3, name: 'ResponseValid', passed: true },
        { gate_id: 4, name: 'EvidenceSound', passed: true },
        { gate_id: 5, name: 'NonDuplicate', passed: true },
        { gate_id: 6, name: 'PermittedMethod', passed: true },
        { gate_id: 7, name: 'Reproducible', passed: true }
      ]
    }
  ];
  fs.writeFileSync(path.join(runDir, 'validated_findings.json'), JSON.stringify(findings, null, 2), 'utf8');

  // 10. report.md
  fs.writeFileSync(path.join(runDir, 'report.md'), '# Scoutr Audit Report for example.com\n\nVerified Findings: 1\n', 'utf8');

  // 11. rce_candidates.json
  const e2eAttempt = {
    attempt_id: 'val-e2e-1',
    profile: 'safe_active',
    timestamp: new Date().toISOString(),
    parameter: 'template',
    correlation_id: 'corr-e2e-101',
    control_request_sent: 'POST /api/v1/export/pdf (probe={{7*8}})',
    positive_request_sent: 'POST /api/v1/export/pdf (probe={{7*7}})',
    marker_expected: '49',
    marker_found: true,
    reflection_excluded: true,
    execution_confirmed: true,
    marker_sent: '${7*7}',
    marker_reflected: false,
    negative_control_sent: '${7*8}',
    negative_control_verified: true,
    reproduction_curl: 'curl -s -X POST -d "template=${7*7}" https://api.example.com/api/v1/export/pdf',
    notes: 'Benign math marker 7*7 evaluated to 49 without payload reflection'
  };

  const rceCandidates = [
    {
      id: 'rce-ssti-101',
      category: 'ssti',
      route: '/api/v1/export/pdf',
      target: 'https://api.example.com/api/v1/export/pdf',
      target_url: 'https://api.example.com/api/v1/export/pdf',
      http_method: 'POST',
      method: 'POST',
      relevant_params: ['template', 'options'],
      parameters: ['template', 'options'],
      confidence: 'high',
      hypothesis: 'User-controlled template string passed to server-side PDF generator',
      suspected_sink: 'Template rendering engine (Jinja2 / FreeMarker)',
      priority_score: 88,
      score_breakdown: {
        base_risk: 40,
        input_exposure: 20,
        auth_modifier: 0,
        tech_cve_modifier: 18,
        chain_modifier: 10,
        explanations: ['High base risk for template injection', 'Unauthenticated public parameter exposure', 'Matched known Spring4Shell advisory']
      },
      validation_status: 'candidate',
      status: 'candidate',
      matching_advisories: [
        {
          advisory: {
            id: 'CVE-2022-22965',
            title: 'Spring Framework RCE via DataBinder (Spring4Shell)',
            affected_product: 'spring-framework',
            vulnerable_range: '>= 5.3.0, < 5.3.18'
          },
          progression_tier: 'component_reachable',
          reachability_reason: 'Endpoint accepts template data'
        }
      ],
      matched_advisories: [
        {
          cve_id: 'CVE-2022-22965',
          product: 'Spring Framework',
          tier: 'ComponentReachable'
        }
      ],
      validation_attempts: [e2eAttempt],
      last_attempt: e2eAttempt
    }
  ];
  fs.writeFileSync(path.join(runDir, 'rce_candidates.json'), JSON.stringify(rceCandidates, null, 2), 'utf8');

  // 12. rce_advisories.json
  const rceAdvisories = [
    {
      cve_id: 'CVE-2022-22965',
      name: 'Spring4Shell RCE',
      product: 'Spring Framework',
      vulnerable_range: '>= 5.3.0, < 5.3.18',
      cvss: 9.8,
      severity: 'critical',
      description: 'Remote code execution in Spring Framework via DataBinder parameter binding',
      affected_routes: ['/api/v1/export/pdf'],
      reachability_notes: 'Endpoint is active and receives user parameters'
    }
  ];
  fs.writeFileSync(path.join(runDir, 'rce_advisories.json'), JSON.stringify(rceAdvisories, null, 2), 'utf8');

  return { runsDir, scopePath, runId };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(__dirname, '..');
  setupTestData(root);
  console.log('Test data created successfully.');
}
