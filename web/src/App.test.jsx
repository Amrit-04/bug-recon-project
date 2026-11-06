import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';

const mockRuns = [
  { id: 'example.com-20261028-101500', target: 'example.com', dir: '.scoutr/runs/example.com-20261028-101500' }
];

const mockScope = {
  in_scope: ['example.com', '*.example.com'],
  out_of_scope: ['admin.example.com'],
  loaded: true
};

const mockFindings = [
  {
    finding: {
      id: 'FINDING-101',
      title: 'Missing Strict-Transport-Security Header',
      target: 'https://api.example.com',
      severity: 'high',
      confidence: 'high'
    },
    status: 'Verified',
    gate_results: [
      { gate_id: 1, name: 'ScopeCheck', passed: true },
      { gate_id: 2, name: 'TargetAlive', passed: true }
    ]
  }
];

const mockTriage = {
  version: '1.0',
  provider: 'lmstudio',
  model: 'llama-3.2-3b-instruct',
  batches: 1,
  counts: {
    likely_true: 1,
    needs_human: 0,
    likely_false: 0
  },
  verdicts: [
    {
      rank: 1,
      finding_id: 'FINDING-101',
      severity: 'high',
      classification: 'likely_true',
      confidence: 95,
      rationale: 'HSTS header omitted on API gateway',
      next_manual_test: 'curl -I https://api.example.com'
    }
  ]
};

const mockProviders = [
  {
    id: 'lmstudio',
    name: 'LM Studio',
    default_endpoint: 'http://127.0.0.1:1234/v1',
    description: 'Local OpenAI-compatible inference with LM Studio',
    port: '1234',
    suggested_models: ['llama-3.2-3b-instruct']
  },
  {
    id: 'llamacpp',
    name: 'llama.cpp',
    default_endpoint: 'http://127.0.0.1:8080/v1',
    description: 'High-throughput local C++ inference via llama.cpp server',
    port: '8080',
    suggested_models: ['qwen2.5-coder-7b']
  }
];

describe('App Dashboard & Local LLM Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn((url, options) => {
      const urlStr = String(url);

      if (urlStr.endsWith('/api/runs')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockRuns) });
      }
      if (urlStr.endsWith('/api/scope')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockScope) });
      }
      if (urlStr.endsWith('/api/llm/providers')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockProviders) });
      }
      if (urlStr.endsWith('/inventory')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(['api.example.com']) });
      }
      if (urlStr.endsWith('/ports')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([{ host: 'api.example.com', port: 443 }]) });
      }
      if (urlStr.endsWith('/httpx')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
      }
      if (urlStr.endsWith('/crawl')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
      }
      if (urlStr.endsWith('/fuzz')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
      }
      if (urlStr.endsWith('/findings')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFindings) });
      }
      if (urlStr.endsWith('/triage') && options?.method === 'POST') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTriage) });
      }
      if (urlStr.endsWith('/triage')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockTriage) });
      }
      if (urlStr.endsWith('/drafts')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(['FINDING-101.md']) });
      }
      if (urlStr.endsWith('/submission_ready')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(null) });
      }
      if (urlStr.endsWith('/api/llm/test') && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ ok: true, endpoint: 'http://127.0.0.1:1234/v1', models: ['llama-3.2-3b-instruct'] })
        });
      }

      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });
  });

  it('renders the dashboard header and title', async () => {
    render(<App />);
    expect(await screen.findByText('scoutr')).toBeInTheDocument();
    expect(screen.getByText('Scope Guard Active')).toBeInTheDocument();
  });

  it('navigates between dashboard tabs', async () => {
    render(<App />);
    
    // Overview tab is initially active
    expect(await screen.findByText(/7-Check Readiness Gate/i)).toBeInTheDocument();

    // Switch to Validated Findings
    const findingsBtn = screen.getByRole('button', { name: /Findings/i });
    fireEvent.click(findingsBtn);
    expect(await screen.findByText('FINDING-101')).toBeInTheDocument();

    // Switch to Scope tab
    const scopeBtn = screen.getByRole('button', { name: /Scope Guard/i });
    fireEvent.click(scopeBtn);
    expect(await screen.findByText('Permitted Target Scope (in_scope)')).toBeInTheDocument();
  });

  it('allows switching providers to LM Studio and llama.cpp in Triage Studio', async () => {
    render(<App />);

    // Switch to AI Triage tab
    const triageBtn = screen.getByRole('button', { name: /AI Triage/i });
    fireEvent.click(triageBtn);

    expect(await screen.findByText('Local LLM Triage Studio')).toBeInTheDocument();

    // Verify LM Studio button is visible
    const lmStudioBtn = screen.getByRole('button', { name: /LM Studio/i });
    expect(lmStudioBtn).toBeInTheDocument();

    // Click llama.cpp provider button
    const llamaCppBtn = screen.getByRole('button', { name: /llama\.cpp/i });
    fireEvent.click(llamaCppBtn);

    // Verify endpoint updates to llama.cpp default endpoint
    const endpointInput = screen.getByPlaceholderText('http://127.0.0.1:1234/v1');
    expect(endpointInput.value).toBe('http://127.0.0.1:8080/v1');
  });

  it('tests connection to local LLM server', async () => {
    render(<App />);

    const triageBtn = screen.getByRole('button', { name: /AI Triage/i });
    fireEvent.click(triageBtn);

    const testBtn = await screen.findByRole('button', { name: /Test Link/i });
    fireEvent.click(testBtn);

    // Verify connection success banner appears
    await waitFor(() => {
      expect(screen.getByText(/Connection verified to/i)).toBeInTheDocument();
    });
  });

  it('runs interactive AI triage and displays verdicts', async () => {
    render(<App />);

    // Wait for initial run loading
    expect(await screen.findByText('example.com')).toBeInTheDocument();

    const triageBtn = screen.getByRole('button', { name: /AI Triage/i });
    fireEvent.click(triageBtn);

    const runBtn = await screen.findByRole('button', { name: /Run AI Triage/i });
    await waitFor(() => expect(runBtn).not.toBeDisabled());
    fireEvent.click(runBtn);

    // Verify triage results table displays
    await waitFor(() => {
      expect(screen.getByText('HSTS header omitted on API gateway')).toBeInTheDocument();
    });
  });

  it('verifies in_scope and out_of_scope rules interactively', async () => {
    render(<App />);

    const scopeBtn = screen.getByRole('button', { name: /Scope Guard/i });
    fireEvent.click(scopeBtn);

    const input = await screen.findByPlaceholderText(/e\.g\. admin\.example\.com/i);

    // In-scope test
    fireEvent.change(input, { target: { value: 'api.example.com' } });
    expect(await screen.findByText(/IN SCOPE: Permitted by in_scope target list/i)).toBeInTheDocument();

    // Out-of-scope test
    fireEvent.change(input, { target: { value: 'admin.example.com' } });
    expect(await screen.findByText(/OUT OF SCOPE: Matched out_of_scope blacklist rule/i)).toBeInTheDocument();
  });
});
