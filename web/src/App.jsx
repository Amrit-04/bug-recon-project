import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Layers, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  FileText, 
  Server, 
  Globe, 
  Search, 
  ExternalLink, 
  Filter, 
  Activity, 
  Lock, 
  ChevronRight, 
  Clock, 
  Cpu, 
  Hash, 
  Code2, 
  Eye, 
  AlertOctagon,
  Copy,
  Check,
  RefreshCw,
  Play,
  Sparkles,
  Zap,
  HelpCircle
} from 'lucide-react';

const SEVERITY_CONFIG = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', badge: 'bg-red-500 text-white' },
  high: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', badge: 'bg-orange-500 text-white' },
  medium: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', badge: 'bg-amber-500 text-white' },
  low: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/30', text: 'text-cyan-400', badge: 'bg-cyan-600 text-white' },
  info: { bg: 'bg-slate-500/10', border: 'border-slate-500/30', text: 'text-slate-400', badge: 'bg-slate-600 text-white' }
};

const STATUS_CONFIG = {
  Verified: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
  NeedsManualReview: { icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
  Suppressed: { icon: XCircle, color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/30' }
};

const DEFAULT_PROVIDERS = [
  {
    id: 'lmstudio',
    name: 'LM Studio',
    default_endpoint: 'http://127.0.0.1:1234/v1',
    description: 'Local OpenAI-compatible inference with LM Studio',
    port: '1234',
    suggested_models: ['llama-3.2-3b-instruct', 'qwen2.5-coder-7b-instruct', 'mistral-7b-instruct-v0.3']
  },
  {
    id: 'llamacpp',
    name: 'llama.cpp',
    default_endpoint: 'http://127.0.0.1:8080/v1',
    description: 'High-throughput local C++ inference via llama.cpp server',
    port: '8080',
    suggested_models: ['qwen2.5-coder-7b', 'llama-3.2-3b', 'mistral-7b']
  },
  {
    id: 'ollama',
    name: 'Ollama',
    default_endpoint: 'http://127.0.0.1:11434',
    description: 'Local daemon for open-weights models',
    port: '11434',
    suggested_models: ['llama3.2', 'qwen2.5-coder:7b', 'mistral']
  },
  {
    id: 'openai',
    name: 'OpenAI / Custom',
    default_endpoint: 'http://127.0.0.1:11434/v1',
    description: 'Any OpenAI-compatible completions endpoint',
    port: 'Custom',
    suggested_models: ['gpt-4o', 'gpt-4o-mini']
  }
];

export default function App() {
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [scope, setScope] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Run artifacts
  const [inventory, setInventory] = useState([]);
  const [ports, setPorts] = useState([]);
  const [httpx, setHttpx] = useState([]);
  const [crawl, setCrawl] = useState([]);
  const [fuzz, setFuzz] = useState([]);
  const [findings, setFindings] = useState([]);
  const [triage, setTriage] = useState(null);
  const [drafts, setDrafts] = useState([]);
  const [submissionReady, setSubmissionReady] = useState(null);

  // LLM Studio & llama.cpp interactive triage state
  const [llmProviders, setLlmProviders] = useState(DEFAULT_PROVIDERS);
  const [selectedProvider, setSelectedProvider] = useState('lmstudio');
  const [llmEndpoint, setLlmEndpoint] = useState('http://127.0.0.1:1234/v1');
  const [llmModel, setLlmModel] = useState('llama-3.2-3b-instruct');
  const [testStatus, setTestStatus] = useState(null);
  const [triaging, setTriaging] = useState(false);
  const [triageError, setTriageError] = useState('');
  const [triageSuccess, setTriageSuccess] = useState('');
  const [showSetupHelp, setShowSetupHelp] = useState(false);
  const [triageFilter, setTriageFilter] = useState('ALL');

  // UI Filters
  const [findingSearch, setFindingSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [activeFinding, setActiveFinding] = useState(null);
  const [activeDraft, setActiveDraft] = useState(null);
  const [draftContent, setDraftContent] = useState('');
  const [reconSubTab, setReconSubTab] = useState('ports');
  const [reconSearch, setReconSearch] = useState('');
  const [scopeTestTarget, setScopeTestTarget] = useState('');
  const [scopeTestResult, setScopeTestResult] = useState(null);
  const [copied, setCopied] = useState(false);

  // Fetch initial runs & scope & LLM providers
  const fetchRunsAndScope = async () => {
    try {
      setRefreshing(true);
      const [runsRes, scopeRes, provRes] = await Promise.all([
        fetch('/api/runs'),
        fetch('/api/scope'),
        fetch('/api/llm/providers').catch(() => null)
      ]);
      if (runsRes.ok) {
        const runData = await runsRes.json();
        setRuns(runData || []);
        if (runData && runData.length > 0 && !selectedRunId) {
          setSelectedRunId(runData[0].id);
        }
      }
      if (scopeRes.ok) {
        const scopeData = await scopeRes.json();
        setScope(scopeData);
      }
      if (provRes && provRes.ok) {
        const provData = await provRes.json();
        if (provData && provData.length > 0) {
          setLlmProviders(provData);
        }
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleProviderSelect = (provId) => {
    setSelectedProvider(provId);
    const list = llmProviders.length > 0 ? llmProviders : DEFAULT_PROVIDERS;
    const p = list.find(x => x.id === provId);
    if (p) {
      setLlmEndpoint(p.default_endpoint);
      if (p.suggested_models && p.suggested_models.length > 0) {
        setLlmModel(p.suggested_models[0]);
      }
    }
    setTestStatus(null);
    setTriageError('');
    setTriageSuccess('');
  };

  const handleTestConnection = async () => {
    setTestStatus({ testing: true });
    setTriageError('');
    try {
      const res = await fetch('/api/llm/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          endpoint: llmEndpoint,
          model: llmModel
        })
      });
      const data = await res.json();
      setTestStatus({
        testing: false,
        ok: data.ok,
        models: data.models || [],
        error: data.error
      });
      if (data.ok && data.models && data.models.length > 0) {
        if (!llmModel || !data.models.includes(llmModel)) {
          setLlmModel(data.models[0]);
        }
      }
    } catch (err) {
      setTestStatus({
        testing: false,
        ok: false,
        error: err.message || 'Connection failed'
      });
    }
  };

  const handleRunTriage = async () => {
    if (!selectedRunId) {
      setTriageError('Please select a workspace run first.');
      return;
    }
    if (!llmModel.trim()) {
      setTriageError('Please specify an LLM model name.');
      return;
    }
    setTriaging(true);
    setTriageError('');
    setTriageSuccess('');
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          endpoint: llmEndpoint,
          model: llmModel.trim()
        })
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const rep = await res.json();
      setTriage(rep);
      setTriageSuccess(`Triage ranking completed successfully using ${selectedProvider} (${llmModel})!`);
      // Refresh findings
      const fRes = await fetch(`/api/runs/${selectedRunId}/findings`);
      if (fRes.ok) {
        const fData = await fRes.json();
        setFindings(fData || []);
      }
      setTimeout(() => setTriageSuccess(''), 6000);
    } catch (err) {
      setTriageError(err.message || 'Triage execution failed');
    } finally {
      setTriaging(false);
    }
  };

  useEffect(() => {
    fetchRunsAndScope();
  }, []);

  // Fetch data for selected run
  useEffect(() => {
    if (!selectedRunId) return;

    const loadRunData = async () => {
      try {
        const [
          invRes,
          portsRes,
          httpxRes,
          crawlRes,
          fuzzRes,
          findingsRes,
          triageRes,
          draftsRes,
          subRes
        ] = await Promise.all([
          fetch(`/api/runs/${selectedRunId}/inventory`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/ports`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/httpx`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/crawl`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/fuzz`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/findings`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/triage`).then(r => r.ok ? r.json() : null),
          fetch(`/api/runs/${selectedRunId}/drafts`).then(r => r.ok ? r.json() : []),
          fetch(`/api/runs/${selectedRunId}/submission_ready`).then(r => r.ok ? r.json() : null)
        ]);

        setInventory(invRes || []);
        setPorts(portsRes || []);
        setHttpx(httpxRes || []);
        setCrawl(crawlRes || []);
        setFuzz(fuzzRes || []);
        setFindings(findingsRes || []);
        setTriage(triageRes);
        setDrafts(draftsRes || []);
        setSubmissionReady(subRes);
      } catch (err) {
        console.error('Failed loading run details:', err);
      }
    };

    loadRunData();
  }, [selectedRunId]);

  // Load draft content when selected
  useEffect(() => {
    if (!selectedRunId || !activeDraft) {
      setDraftContent('');
      return;
    }
    fetch(`/api/runs/${selectedRunId}/drafts/${activeDraft}`)
      .then(r => r.ok ? r.text() : 'Failed to load draft.')
      .then(setDraftContent)
      .catch(() => setDraftContent('Failed to load draft.'));
  }, [selectedRunId, activeDraft]);

  // Test target against scope
  const testScopeRule = (target) => {
    if (!scope || !target) {
      setScopeTestResult(null);
      return;
    }
    const clean = target.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
    
    // Check out of scope first
    const isOut = scope.out_of_scope?.some(rule => {
      const r = rule.toLowerCase();
      if (r.startsWith('*.')) return clean.endsWith(r.slice(1)) || clean === r.slice(2);
      return clean === r;
    });

    if (isOut) {
      setScopeTestResult({ inScope: false, reason: 'Matched out_of_scope blacklist rule' });
      return;
    }

    // Check in scope
    const isIn = scope.in_scope?.some(rule => {
      const r = rule.toLowerCase();
      if (r.startsWith('*.')) return clean.endsWith(r.slice(1)) || clean === r.slice(2);
      return clean === r;
    });

    if (isIn) {
      setScopeTestResult({ inScope: true, reason: 'Permitted by in_scope target list' });
    } else {
      setScopeTestResult({ inScope: false, reason: 'Not found in in_scope targets' });
    }
  };

  const selectedRun = runs.find(r => r.id === selectedRunId) || { id: selectedRunId, target: 'No run selected' };

  // Calculate stats
  const verifiedCount = findings.filter(f => f.status === 'Verified').length;
  const reviewCount = findings.filter(f => f.status === 'NeedsManualReview').length;
  const suppressedCount = findings.filter(f => f.status === 'Suppressed').length;

  const severityCounts = findings.reduce((acc, f) => {
    const sev = (f.finding?.severity || 'info').toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  // Filtered findings
  const filteredFindings = findings.filter(vf => {
    const f = vf.finding;
    if (!f) return false;
    if (statusFilter !== 'ALL' && vf.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) return false;
    if (findingSearch) {
      const q = findingSearch.toLowerCase();
      const matchTitle = f.title?.toLowerCase().includes(q);
      const matchTarget = f.target?.toLowerCase().includes(q);
      const matchRule = f.rule_id?.toLowerCase().includes(q);
      const matchID = f.id?.toLowerCase().includes(q);
      const matchImpact = f.impact?.toLowerCase().includes(q);
      return matchTitle || matchTarget || matchRule || matchID || matchImpact;
    }
    return true;
  });

  return (
    <div className="flex flex-col min-h-screen bg-[#090d16] text-slate-100">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#0d1424]/90 backdrop-blur sticky top-0 z-40 px-6 py-3">
        <div className="flex flex-wrap items-center justify-between gap-4 max-w-7xl mx-auto">
          {/* Logo & Product Title */}
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 shadow-lg shadow-cyan-500/20 text-white font-black tracking-wider">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white font-mono">scoutr</h1>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  Unified Recon & Gate
                </span>
              </div>
              <p className="text-xs text-slate-400">Deterministic Reconnaissance & 7-Check Readiness Gate</p>
            </div>
          </div>

          {/* Run Selector & Quick Actions */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-700/60 rounded-lg px-3 py-1.5 text-xs">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400 font-medium">Audit Run:</span>
              {runs.length > 0 ? (
                <select 
                  value={selectedRunId} 
                  onChange={(e) => setSelectedRunId(e.target.value)}
                  className="bg-transparent text-slate-200 font-mono font-medium focus:outline-none cursor-pointer"
                >
                  {runs.map(r => (
                    <option key={r.id} value={r.id} className="bg-slate-900 text-slate-200">
                      {r.target} ({r.id.split('-').slice(1).join('-') || r.id})
                    </option>
                  ))}
                </select>
              ) : (
                <span className="text-slate-500 italic">No workspace runs found</span>
              )}
            </div>

            {/* Scope Guard Status Badge */}
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Scope Guard Active</span>
            </div>

            <button
              onClick={fetchRunsAndScope}
              disabled={refreshing}
              className="p-2 text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/60 rounded-lg transition"
              title="Refresh Runs"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Navigation Tabs */}
      <nav className="border-b border-slate-800 bg-[#0b101d] px-6">
        <div className="flex gap-1 max-w-7xl mx-auto overflow-x-auto text-sm font-medium">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'recon', label: 'Attack Surface', icon: Globe, count: ports.length + httpx.length },
            { id: 'findings', label: 'Readiness Gate & Findings', icon: Shield, count: findings.length },
            { id: 'triage', label: 'Tier 2 AI Triage', icon: Cpu, count: triage?.verdicts?.length || 0 },
            { id: 'drafts', label: 'Drafts & Approval (Tier 3)', icon: FileText, count: drafts.length },
            { id: 'scope', label: 'Scope Guard', icon: Lock }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 py-3 px-4 border-b-2 font-medium transition whitespace-nowrap ${
                  active 
                    ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5' 
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
                {tab.count !== undefined && tab.count > 0 && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                    active ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-24 text-slate-500 gap-3">
            <RefreshCw className="w-8 h-8 animate-spin text-cyan-500" />
            <p className="text-sm">Loading audit run workspace...</p>
          </div>
        ) : (
          <>
            {/* OVERVIEW TAB */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Target banner */}
                <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold">Active Run Target</span>
                    <h2 className="text-2xl font-bold font-mono text-white mt-0.5">{selectedRun.target}</h2>
                    <p className="text-xs text-slate-400 mt-1 font-mono">Workspace ID: {selectedRun.id}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Scope Enforced at Transport
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      <Lock className="w-3.5 h-3.5" /> 7-Check Authority Gate
                    </span>
                  </div>
                </div>

                {/* Primary Metric KPI Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400 uppercase font-semibold">Verified Findings</p>
                      <h3 className="text-2xl font-bold text-emerald-400 font-mono mt-1">{verifiedCount}</h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">Passed 7-Check readiness gate</p>
                    </div>
                    <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <CheckCircle2 className="w-5 h-5" />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400 uppercase font-semibold">Needs Manual Review</p>
                      <h3 className="text-2xl font-bold text-amber-400 font-mono mt-1">{reviewCount}</h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">Static headers or ambiguous</p>
                    </div>
                    <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      <AlertTriangle className="w-5 h-5" />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400 uppercase font-semibold">Suppressed (False +)</p>
                      <h3 className="text-2xl font-bold text-slate-400 font-mono mt-1">{suppressedCount}</h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">Filtered by soft-404/scope</p>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-800 text-slate-400 border border-slate-700">
                      <XCircle className="w-5 h-5" />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <p className="text-xs text-slate-400 uppercase font-semibold">Surface Discovered</p>
                      <h3 className="text-2xl font-bold text-cyan-400 font-mono mt-1">{ports.length + httpx.length}</h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">{ports.length} ports, {httpx.length} HTTP hosts</p>
                    </div>
                    <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      <Globe className="w-5 h-5" />
                    </div>
                  </div>
                </div>

                {/* Severity Breakdown Bar */}
                <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wide">Findings Severity Distribution</h3>
                    <span className="text-xs text-slate-400 font-mono">{findings.length} total raw/grouped findings</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    {['critical', 'high', 'medium', 'low', 'info'].map(s => {
                      const count = severityCounts[s] || 0;
                      const cfg = SEVERITY_CONFIG[s];
                      return (
                        <div key={s} className={`p-3 rounded-lg border ${cfg.border} ${cfg.bg}`}>
                          <div className="flex items-center justify-between">
                            <span className="text-xs uppercase font-bold tracking-wider text-slate-300">{s}</span>
                            <span className={`text-base font-bold font-mono ${cfg.text}`}>{count}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Recon Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Technology Stack Detected */}
                  <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
                    <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <Server className="w-4 h-4 text-cyan-400" /> Technologies & Services Identified
                    </h3>
                    <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto">
                      {httpx.flatMap(h => h.tech || []).filter((v, i, a) => a.indexOf(v) === i).length > 0 ? (
                        httpx.flatMap(h => h.tech || []).filter((v, i, a) => a.indexOf(v) === i).map(t => (
                          <span key={t} className="px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700/80">
                            {t}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-slate-500 italic">No web technologies recorded in httpx.json for this run.</span>
                      )}
                    </div>
                  </div>

                  {/* Discovered Services / Ports */}
                  <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
                    <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-blue-400" /> Discovered Open Ports (naabu + nmap)
                    </h3>
                    {ports.length > 0 ? (
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {ports.slice(0, 10).map((p, idx) => (
                          <div key={idx} className="flex items-center justify-between text-xs py-1 px-2 rounded bg-slate-950/60 border border-slate-800/80 font-mono">
                            <span className="text-cyan-300">{p.host}:{p.port}</span>
                            <span className="text-slate-400">{p.service || 'unknown'} {p.product && `(${p.product})`}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-slate-500 italic">No ports recorded in ports.json for this run.</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ATTACK SURFACE TAB */}
            {activeTab === 'recon' && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
                  <div className="flex gap-2 text-xs font-medium">
                    {[
                      { id: 'ports', label: 'Ports & Services', count: ports.length },
                      { id: 'httpx', label: 'Live HTTP Hosts', count: httpx.length },
                      { id: 'crawl', label: 'Crawled URLs', count: crawl.length },
                      { id: 'fuzz', label: 'Path Candidates', count: fuzz.length },
                      { id: 'inventory', label: 'Subdomains / Inventory', count: inventory.length }
                    ].map(sub => (
                      <button
                        key={sub.id}
                        onClick={() => setReconSubTab(sub.id)}
                        className={`px-3 py-1.5 rounded-lg transition ${
                          reconSubTab === sub.id 
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                            : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                        }`}
                      >
                        {sub.label} ({sub.count})
                      </button>
                    ))}
                  </div>

                  <div className="relative w-64">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
                    <input
                      type="text"
                      placeholder="Filter records..."
                      value={reconSearch}
                      onChange={e => setReconSearch(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                {/* Sub Tab: Ports */}
                {reconSubTab === 'ports' && (
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Host</th>
                          <th className="py-2.5 px-4 font-semibold">Port</th>
                          <th className="py-2.5 px-4 font-semibold">Service</th>
                          <th className="py-2.5 px-4 font-semibold">Product & Version</th>
                          <th className="py-2.5 px-4 font-semibold">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {ports.filter(p => !reconSearch || `${p.host}:${p.port} ${p.service}`.toLowerCase().includes(reconSearch.toLowerCase())).map((p, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-4 text-cyan-400">{p.host}</td>
                            <td className="py-2.5 px-4 text-white font-bold">{p.port}</td>
                            <td className="py-2.5 px-4 text-slate-300">{p.service || '—'}</td>
                            <td className="py-2.5 px-4 text-slate-400">{p.product ? `${p.product} ${p.version || ''}` : '—'}</td>
                            <td className="py-2.5 px-4 text-slate-500">{p.source || 'naabu'}</td>
                          </tr>
                        ))}
                        {ports.length === 0 && (
                          <tr><td colSpan="5" className="py-8 text-center text-slate-500 italic">No port discovery records.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Sub Tab: HTTPX */}
                {reconSubTab === 'httpx' && (
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Status</th>
                          <th className="py-2.5 px-4 font-semibold">URL</th>
                          <th className="py-2.5 px-4 font-semibold">Page Title</th>
                          <th className="py-2.5 px-4 font-semibold">Server</th>
                          <th className="py-2.5 px-4 font-semibold">Technologies</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {httpx.filter(h => !reconSearch || `${h.url} ${h.title} ${h.server}`.toLowerCase().includes(reconSearch.toLowerCase())).map((h, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                h.status_code >= 200 && h.status_code < 300 ? 'bg-emerald-500/20 text-emerald-400' :
                                h.status_code >= 300 && h.status_code < 400 ? 'bg-blue-500/20 text-blue-400' :
                                'bg-amber-500/20 text-amber-400'
                              }`}>
                                {h.status_code || 200}
                              </span>
                            </td>
                            <td className="py-2.5 px-4 text-cyan-300">
                              <a href={h.url} target="_blank" rel="noreferrer" className="hover:underline flex items-center gap-1">
                                {h.url} <ExternalLink className="w-3 h-3 text-slate-500" />
                              </a>
                            </td>
                            <td className="py-2.5 px-4 text-slate-300 max-w-xs truncate">{h.title || '—'}</td>
                            <td className="py-2.5 px-4 text-slate-400">{h.webserver || h.server || '—'}</td>
                            <td className="py-2.5 px-4 text-slate-400">
                              <div className="flex flex-wrap gap-1">
                                {(h.tech || []).map(t => (
                                  <span key={t} className="px-1.5 py-0.2 bg-slate-800 text-[10px] rounded text-slate-300">{t}</span>
                                ))}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Sub Tab: Crawl */}
                {reconSubTab === 'crawl' && (
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Method</th>
                          <th className="py-2.5 px-4 font-semibold">Endpoint</th>
                          <th className="py-2.5 px-4 font-semibold">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {crawl.filter(c => !reconSearch || c.endpoint?.toLowerCase().includes(reconSearch.toLowerCase())).map((c, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-4 text-blue-400 font-bold">{c.method || 'GET'}</td>
                            <td className="py-2.5 px-4 text-cyan-300 break-all">{c.endpoint}</td>
                            <td className="py-2.5 px-4 text-slate-500">{c.source || 'katana'}</td>
                          </tr>
                        ))}
                        {crawl.length === 0 && (
                          <tr><td colSpan="3" className="py-8 text-center text-slate-500 italic">No crawled endpoints recorded.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Sub Tab: Fuzz */}
                {reconSubTab === 'fuzz' && (
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Status</th>
                          <th className="py-2.5 px-4 font-semibold">URL</th>
                          <th className="py-2.5 px-4 font-semibold">Length</th>
                          <th className="py-2.5 px-4 font-semibold">Words / Lines</th>
                          <th className="py-2.5 px-4 font-semibold">Redirect Location</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {fuzz.filter(f => !reconSearch || f.url?.toLowerCase().includes(reconSearch.toLowerCase())).map((f, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-4">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-200">
                                {f.status}
                              </span>
                            </td>
                            <td className="py-2.5 px-4 text-cyan-300 break-all">{f.url}</td>
                            <td className="py-2.5 px-4 text-slate-400">{f.length} B</td>
                            <td className="py-2.5 px-4 text-slate-500">{f.words} w / {f.lines} l</td>
                            <td className="py-2.5 px-4 text-slate-400">{f.redirect_location || '—'}</td>
                          </tr>
                        ))}
                        {fuzz.length === 0 && (
                          <tr><td colSpan="5" className="py-8 text-center text-slate-500 italic">No path candidates recorded.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Sub Tab: Inventory */}
                {reconSubTab === 'inventory' && (
                  <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase mb-3">Discovered Target Inventory ({inventory.length})</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 font-mono text-xs">
                      {inventory.map((host, idx) => (
                        <div key={idx} className="p-2 rounded bg-slate-950/80 border border-slate-800/80 text-cyan-300 truncate">
                          {host}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 7-CHECK GATE & FINDINGS TAB */}
            {activeTab === 'findings' && (
              <div className="space-y-4">
                {/* Search & Filters */}
                <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Status filters */}
                    <div className="flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs font-medium">
                      {['ALL', 'Verified', 'NeedsManualReview', 'Suppressed'].map(st => (
                        <button
                          key={st}
                          onClick={() => setStatusFilter(st)}
                          className={`px-3 py-1 rounded-md transition ${
                            statusFilter === st 
                              ? 'bg-cyan-600 text-white font-semibold' 
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {st === 'ALL' ? 'All Status' : st}
                        </button>
                      ))}
                    </div>

                    {/* Severity filters */}
                    <div className="flex rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs font-medium">
                      {['ALL', 'critical', 'high', 'medium', 'low'].map(sev => (
                        <button
                          key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className={`px-2.5 py-1 rounded-md uppercase transition ${
                            severityFilter === sev 
                              ? 'bg-slate-700 text-white font-semibold' 
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="relative w-72">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
                    <input
                      type="text"
                      placeholder="Search title, target, rule, CWE..."
                      value={findingSearch}
                      onChange={e => setFindingSearch(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                {/* Findings Table */}
                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 font-mono">
                      <tr>
                        <th className="py-3 px-4 font-semibold">Severity</th>
                        <th className="py-3 px-4 font-semibold">Gate Status</th>
                        <th className="py-3 px-4 font-semibold">ID / Rule</th>
                        <th className="py-3 px-4 font-semibold">Finding Title</th>
                        <th className="py-3 px-4 font-semibold">Target / Path</th>
                        <th className="py-3 px-4 font-semibold text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {filteredFindings.map((vf, idx) => {
                        const f = vf.finding;
                        const sev = (f.severity || 'info').toLowerCase();
                        const sCfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info;
                        const stCfg = STATUS_CONFIG[vf.status] || STATUS_CONFIG.NeedsManualReview;
                        const StatusIcon = stCfg.icon;

                        return (
                          <tr key={idx} className="hover:bg-slate-800/30 transition cursor-pointer" onClick={() => setActiveFinding(vf)}>
                            <td className="py-3 px-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sCfg.badge}`}>
                                {sev}
                              </span>
                            </td>
                            <td className="py-3 px-4">
                              <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-medium border ${stCfg.bg} ${stCfg.border} ${stCfg.color}`}>
                                <StatusIcon className="w-3 h-3" />
                                {vf.status}
                              </span>
                            </td>
                            <td className="py-3 px-4">
                              <span className="font-bold text-white">{f.id}</span>
                              <div className="text-[10px] text-slate-500 truncate max-w-[120px]">{f.rule_id || f.check_name}</div>
                            </td>
                            <td className="py-3 px-4 font-sans font-medium text-slate-200 max-w-xs truncate">
                              {f.title}
                            </td>
                            <td className="py-3 px-4 text-cyan-400 truncate max-w-xs">
                              {f.target}{f.path || ''}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <button 
                                onClick={(e) => { e.stopPropagation(); setActiveFinding(vf); }}
                                className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition"
                              >
                                <ChevronRight className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                      {filteredFindings.length === 0 && (
                        <tr>
                          <td colSpan="6" className="py-12 text-center text-slate-500 italic">
                            No findings matching the filter criteria.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TIER 2 AI TRIAGE TAB */}
            {activeTab === 'triage' && (
              <div className="space-y-6">
                {/* Local LLM Interactive Workbench Card */}
                <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 shadow-xl space-y-5">
                  <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          Tier 2 Agent-Assisted
                        </span>
                        <span className="text-xs text-slate-500">•</span>
                        <span className="text-xs font-mono text-slate-400">Offline Local Inference</span>
                      </div>
                      <h3 className="text-lg font-bold text-white mt-1 flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-cyan-400" />
                        Local LLM Triage Studio
                      </h3>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Connect LM Studio or llama.cpp to rank findings and generate targeted manual test instructions without cloud APIs.
                      </p>
                    </div>

                    <button
                      onClick={() => setShowSetupHelp(!showSetupHelp)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 transition"
                    >
                      <HelpCircle className="w-4 h-4 text-cyan-400" />
                      <span>{showSetupHelp ? 'Hide Setup Guide' : 'Connection Guide'}</span>
                    </button>
                  </div>

                  {/* Setup Help Collapsible */}
                  {showSetupHelp && (
                    <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/20 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs animate-in fade-in duration-200">
                      <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1.5">
                        <div className="font-bold text-cyan-300 flex items-center gap-1.5">
                          <Server className="w-4 h-4" /> LM Studio
                        </div>
                        <ol className="list-decimal list-inside text-slate-400 space-y-1 text-[11px] leading-relaxed">
                          <li>Open LM Studio and load a model</li>
                          <li>Click the <strong className="text-slate-300">Developer / Server</strong> tab</li>
                          <li>Start server on port <code className="text-cyan-300">1234</code></li>
                          <li>CORS is enabled by default</li>
                        </ol>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1.5">
                        <div className="font-bold text-cyan-300 flex items-center gap-1.5">
                          <Terminal className="w-4 h-4" /> llama.cpp
                        </div>
                        <div className="text-slate-400 space-y-1 text-[11px] leading-relaxed">
                          <p>Run the native C++ server:</p>
                          <pre className="p-1.5 bg-black/60 rounded text-[10px] text-cyan-200 font-mono overflow-x-auto">
                            llama-server -m model.gguf -c 4096 --port 8080
                          </pre>
                          <p>Endpoint: <code className="text-cyan-300">http://127.0.0.1:8080/v1</code></p>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1.5">
                        <div className="font-bold text-cyan-300 flex items-center gap-1.5">
                          <Layers className="w-4 h-4" /> Ollama
                        </div>
                        <div className="text-slate-400 space-y-1 text-[11px] leading-relaxed">
                          <p>Start local Ollama daemon:</p>
                          <pre className="p-1.5 bg-black/60 rounded text-[10px] text-cyan-200 font-mono">
                            ollama run llama3.2
                          </pre>
                          <p>Native API: <code className="text-cyan-300">http://127.0.0.1:11434</code></p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Provider Selection Tabs */}
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Select Local Model Provider
                    </label>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {llmProviders.map(prov => {
                        const isSelected = selectedProvider === prov.id;
                        return (
                          <button
                            key={prov.id}
                            onClick={() => handleProviderSelect(prov.id)}
                            className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
                              isSelected
                                ? 'bg-cyan-500/10 border-cyan-500/50 text-white ring-1 ring-cyan-500/30'
                                : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/60 text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            <div className="flex items-center justify-between w-full">
                              <span className="font-bold text-sm">{prov.name}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                                isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-500'
                              }`}>
                                {prov.port ? `:${prov.port}` : 'Local'}
                              </span>
                            </div>
                            <span className="text-[11px] text-slate-500 mt-1 line-clamp-1">{prov.description}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Configuration Row: Endpoint + Model Input + Actions */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
                    {/* Endpoint Input */}
                    <div className="md:col-span-5 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                          Endpoint URL
                        </label>
                        <button
                          onClick={() => {
                            const p = llmProviders.find(x => x.id === selectedProvider);
                            if (p) setLlmEndpoint(p.default_endpoint);
                          }}
                          className="text-[10px] text-cyan-400 hover:underline"
                        >
                          Reset Default
                        </button>
                      </div>
                      <input
                        type="text"
                        value={llmEndpoint}
                        onChange={e => setLlmEndpoint(e.target.value)}
                        placeholder="http://127.0.0.1:1234/v1"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    {/* Model Input & Quick Selection */}
                    <div className="md:col-span-4 space-y-1.5">
                      <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                        Model Identifier
                      </label>
                      {testStatus?.models && testStatus.models.length > 0 ? (
                        <select
                          value={llmModel}
                          onChange={e => setLlmModel(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                        >
                          {testStatus.models.map(m => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type="text"
                          value={llmModel}
                          onChange={e => setLlmModel(e.target.value)}
                          placeholder="e.g. llama-3.2-3b-instruct"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                        />
                      )}
                    </div>

                    {/* Action Buttons */}
                    <div className="md:col-span-3 flex items-center gap-2">
                      <button
                        onClick={handleTestConnection}
                        disabled={testStatus?.testing}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition disabled:opacity-50"
                      >
                        <Zap className={`w-3.5 h-3.5 text-amber-400 ${testStatus?.testing ? 'animate-pulse' : ''}`} />
                        <span>{testStatus?.testing ? 'Testing...' : 'Test Link'}</span>
                      </button>

                      <button
                        onClick={handleRunTriage}
                        disabled={triaging || findings.length === 0}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-bold text-white shadow-lg shadow-cyan-900/30 transition disabled:opacity-40"
                      >
                        {triaging ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Triaging...</span>
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5 text-cyan-200" />
                            <span>Run AI Triage</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Model Suggestion Pills */}
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                    <span className="font-semibold text-slate-500">Suggested:</span>
                    {(llmProviders.find(p => p.id === selectedProvider)?.suggested_models || []).map(m => (
                      <button
                        key={m}
                        onClick={() => setLlmModel(m)}
                        className={`px-2 py-0.5 rounded font-mono border transition ${
                          llmModel === m 
                            ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300' 
                            : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>

                  {/* Connection Test Result Badge */}
                  {testStatus && (
                    <div className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
                      testStatus.ok 
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
                        : 'bg-red-500/10 border-red-500/30 text-red-300'
                    }`}>
                      <div className="flex items-center gap-2">
                        {testStatus.ok ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> : <XCircle className="w-4 h-4 flex-shrink-0" />}
                        <span>
                          {testStatus.ok 
                            ? `Connection verified to ${selectedProvider} at ${testStatus.endpoint}. ${testStatus.models?.length || 0} loaded model(s) detected.`
                            : `Connection check failed: ${testStatus.error}`
                          }
                        </span>
                      </div>
                      {!testStatus.ok && (
                        <button 
                          onClick={() => setShowSetupHelp(true)}
                          className="text-[11px] underline text-red-200 hover:text-white"
                        >
                          View Setup Tips
                        </button>
                      )}
                    </div>
                  )}

                  {/* Triaging Progress Indicator */}
                  {triaging && (
                    <div className="p-4 rounded-xl border border-cyan-500/40 bg-cyan-950/20 space-y-2 animate-pulse">
                      <div className="flex items-center justify-between text-xs font-mono text-cyan-300">
                        <span className="flex items-center gap-2 font-bold">
                          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                          Processing Validated Findings with {selectedProvider}...
                        </span>
                        <span>Evaluating batches</span>
                      </div>
                      <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-400 w-3/4 animate-pulse"></div>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Batching evidence, evaluating plausibility, and enforcing deterministic 7-Check gate hard rules...
                      </p>
                    </div>
                  )}

                  {/* Feedback Banners */}
                  {triageSuccess && (
                    <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-xs font-mono flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>{triageSuccess}</span>
                    </div>
                  )}

                  {triageError && (
                    <div className="p-3 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs font-mono flex items-center gap-2">
                      <AlertOctagon className="w-4 h-4" />
                      <span>{triageError}</span>
                    </div>
                  )}

                  {/* Deterministic Safety Guarantee Callout */}
                  <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                    <span className="flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-emerald-400" />
                      Scope Guard Guarantee: LLM receives only redacted finding evidence.
                    </span>
                    <span>7-Check Gate remains supreme authority.</span>
                  </div>
                </div>

                {/* Triage Results View */}
                {triage ? (
                  <>
                    {/* Triage Overview Card */}
                    <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                      <div>
                        <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold">Tier 2 Model Ranking Results</span>
                        <h3 className="text-lg font-bold text-white mt-0.5 flex items-center gap-2">
                          <Cpu className="w-5 h-5 text-cyan-400" />
                          Model: <span className="font-mono text-cyan-300">{triage.model || 'local'}</span>
                          <span className="text-xs font-normal text-slate-400">({triage.provider || 'local'})</span>
                        </h3>
                        <p className="text-xs text-slate-400 mt-1">
                          Processed {triage.batches || 0} batches ({triage.eligible_findings || 0} eligible findings). Gate verdicts are immutable.
                        </p>
                      </div>

                      <div className="flex gap-3 text-center font-mono">
                        <button
                          onClick={() => setTriageFilter(triageFilter === 'likely_true' ? 'ALL' : 'likely_true')}
                          className={`px-3 py-1.5 rounded-lg border transition ${
                            triageFilter === 'likely_true' 
                              ? 'bg-emerald-500/25 border-emerald-500 text-emerald-300' 
                              : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                          }`}
                        >
                          <div className="text-lg font-bold">{triage.counts?.likely_true || 0}</div>
                          <div className="text-[10px] uppercase font-sans">likely_true</div>
                        </button>
                        <button
                          onClick={() => setTriageFilter(triageFilter === 'needs_human' ? 'ALL' : 'needs_human')}
                          className={`px-3 py-1.5 rounded-lg border transition ${
                            triageFilter === 'needs_human' 
                              ? 'bg-amber-500/25 border-amber-500 text-amber-300' 
                              : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                          }`}
                        >
                          <div className="text-lg font-bold">{triage.counts?.needs_human || 0}</div>
                          <div className="text-[10px] uppercase font-sans">needs_human</div>
                        </button>
                        <button
                          onClick={() => setTriageFilter(triageFilter === 'likely_false' ? 'ALL' : 'likely_false')}
                          className={`px-3 py-1.5 rounded-lg border transition ${
                            triageFilter === 'likely_false' 
                              ? 'bg-slate-700 border-slate-500 text-slate-200' 
                              : 'bg-slate-800 border-slate-700 text-slate-400'
                          }`}
                        >
                          <div className="text-lg font-bold">{triage.counts?.likely_false || 0}</div>
                          <div className="text-[10px] uppercase font-sans">likely_false</div>
                        </button>
                      </div>
                    </div>

                    {/* Verdicts Table */}
                    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-4 font-semibold">Rank</th>
                            <th className="py-2.5 px-4 font-semibold">Classification</th>
                            <th className="py-2.5 px-4 font-semibold">Severity</th>
                            <th className="py-2.5 px-4 font-semibold">Finding ID</th>
                            <th className="py-2.5 px-4 font-semibold">Confidence</th>
                            <th className="py-2.5 px-4 font-semibold">Rationale & Manual Verification</th>
                            <th className="py-2.5 px-4 font-semibold">Hard Rule Veto</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {(triage.verdicts || [])
                            .filter(v => triageFilter === 'ALL' || v.classification === triageFilter)
                            .map((v, idx) => (
                              <tr key={idx} className="hover:bg-slate-800/30 transition">
                                <td className="py-3 px-4 font-bold text-slate-300">#{v.rank}</td>
                                <td className="py-3 px-4">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    v.classification === 'likely_true' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                                    v.classification === 'needs_human' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                    'bg-slate-800 text-slate-400 border border-slate-700'
                                  }`}>
                                    {v.classification}
                                  </span>
                                </td>
                                <td className="py-3 px-4 text-orange-400 font-bold uppercase">{v.severity}</td>
                                <td className="py-3 px-4 text-white font-bold">{v.finding_id}</td>
                                <td className="py-3 px-4">
                                  <div className="flex items-center gap-1.5">
                                    <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                      <div className="h-full bg-cyan-400" style={{ width: `${v.confidence}%` }}></div>
                                    </div>
                                    <span className="text-[11px] text-slate-400">{v.confidence}%</span>
                                  </div>
                                </td>
                                <td className="py-3 px-4 font-sans text-slate-300 max-w-sm">
                                  <p className="text-xs line-clamp-2">{v.rationale}</p>
                                  {v.next_manual_test && (
                                    <div className="mt-1 flex items-center justify-between p-1.5 rounded bg-black/40 border border-slate-800 font-mono text-[10px] text-cyan-300">
                                      <span className="truncate">{v.next_manual_test}</span>
                                      <button 
                                        onClick={() => {
                                          navigator.clipboard.writeText(v.next_manual_test);
                                        }}
                                        title="Copy test command"
                                        className="ml-1 text-slate-500 hover:text-white"
                                      >
                                        <Copy className="w-3 h-3" />
                                      </button>
                                    </div>
                                  )}
                                </td>
                                <td className="py-3 px-4">
                                  {v.hard_rule_overrides && v.hard_rule_overrides.length > 0 ? (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                      {v.hard_rule_overrides.join(', ')}
                                    </span>
                                  ) : (
                                    <span className="text-slate-600">—</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                ) : (
                  <div className="p-12 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-900/30 text-slate-400 space-y-4">
                    <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto text-cyan-400">
                      <Cpu className="w-6 h-6" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="font-bold text-white text-base">Ready for Local Model Triage</h3>
                      <p className="text-xs max-w-md mx-auto text-slate-400">
                        This run has <strong className="text-slate-200">{findings.length} findings</strong> validated by the 7-Check gate. Select LM Studio or llama.cpp above and click <span className="text-cyan-400 font-semibold">Run AI Triage</span> to generate rankings.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* DRAFTS & HUMAN APPROVAL TAB */}
            {activeTab === 'drafts' && (
              <div className="space-y-6">
                {/* Tier 3 Notice */}
                <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3 text-amber-200">
                  <Lock className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                  <div className="text-xs space-y-1">
                    <p className="font-bold">Tier 3 Human Authority Guarantee</p>
                    <p className="text-amber-300/80">
                      scoutr never contacts third-party platforms or submits reports automatically. Reports under <code className="bg-amber-950/80 px-1 py-0.2 rounded font-mono">reports/drafts/</code> require manual operator review and verification.
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Draft Files List */}
                  <div className="space-y-2 lg:col-span-1">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Generated Report Drafts ({drafts.length})
                    </h4>
                    <div className="space-y-1.5">
                      {drafts.map((d, idx) => (
                        <button
                          key={idx}
                          onClick={() => setActiveDraft(d)}
                          className={`w-full text-left p-3 rounded-lg border font-mono text-xs transition flex items-center justify-between ${
                            activeDraft === d 
                              ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300' 
                              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/60 text-slate-300'
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate">
                            <FileText className="w-4 h-4 flex-shrink-0 text-slate-500" />
                            <span className="truncate">{d}</span>
                          </div>
                          <ChevronRight className="w-3.5 h-3.5 flex-shrink-0 text-slate-500" />
                        </button>
                      ))}
                      {drafts.length === 0 && (
                        <p className="text-xs text-slate-500 italic p-4 text-center border border-dashed border-slate-800 rounded-lg">
                          No drafts generated. Run <br /><code className="text-cyan-400">scoutr report --draft --from ...</code>
                        </p>
                      )}
                    </div>

                    {/* Submission Queue Artifact */}
                    {submissionReady && (
                      <div className="mt-6 p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 space-y-2">
                        <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Local Submission Queue</span>
                        </div>
                        <p className="text-[11px] text-slate-400">
                          {submissionReady.entries?.length || 0} findings queued as <code className="text-emerald-300">submission_ready</code>.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Draft Preview Viewer */}
                  <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950 p-5 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <span className="text-xs font-semibold text-slate-300 uppercase font-mono">
                        {activeDraft ? `Previewing: ${activeDraft}` : 'Select a draft to view'}
                      </span>
                      {activeDraft && (
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(draftContent);
                            setCopied(true);
                            setTimeout(() => setCopied(false), 2000);
                          }}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
                        >
                          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copied ? 'Copied' : 'Copy Markdown'}</span>
                        </button>
                      )}
                    </div>
                    {activeDraft ? (
                      <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap overflow-y-auto max-h-[500px] leading-relaxed">
                        {draftContent}
                      </pre>
                    ) : (
                      <div className="py-24 text-center text-slate-600 text-xs italic">
                        Select a draft report on the left to read narrative fields and redacted evidence.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* SCOPE GUARD TAB */}
            {activeTab === 'scope' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* In Scope */}
                  <div className="p-5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-3">
                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                      <CheckCircle2 className="w-4 h-4" />
                      <h3>Permitted Target Scope (in_scope)</h3>
                    </div>
                    <p className="text-xs text-slate-400">All outbound network traffic is checked against this list at the transport layer.</p>
                    <div className="space-y-1.5 font-mono text-xs">
                      {scope?.in_scope?.map((rule, idx) => (
                        <div key={idx} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-emerald-300">
                          {rule}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Out of Scope */}
                  <div className="p-5 rounded-xl border border-red-500/20 bg-red-500/5 space-y-3">
                    <div className="flex items-center gap-2 text-red-400 font-bold text-sm">
                      <XCircle className="w-4 h-4" />
                      <h3>Restricted Infrastructure (out_of_scope)</h3>
                    </div>
                    <p className="text-xs text-slate-400">Strictly excluded targets. Out-of-scope always overrides in-scope rules.</p>
                    <div className="space-y-1.5 font-mono text-xs">
                      {scope?.out_of_scope?.map((rule, idx) => (
                        <div key={idx} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-red-300">
                          {rule}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Interactive Scope Rule Tester */}
                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Interactive Scope Verification Tester
                  </h4>
                  <p className="text-xs text-slate-400">
                    Test any domain or URL against the loaded YAML scope policy to simulate Gate 1 verification.
                  </p>
                  <div className="flex gap-2 max-w-xl">
                    <input
                      type="text"
                      placeholder="e.g. admin.example.com or api.example.com"
                      value={scopeTestTarget}
                      onChange={e => {
                        setScopeTestTarget(e.target.value);
                        testScopeRule(e.target.value);
                      }}
                      className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  {scopeTestResult && (
                    <div className={`p-3 rounded-lg border text-xs font-mono flex items-center gap-2 max-w-xl ${
                      scopeTestResult.inScope 
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
                        : 'bg-red-500/10 border-red-500/30 text-red-300'
                    }`}>
                      {scopeTestResult.inScope ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                      <span>{scopeTestResult.inScope ? 'IN SCOPE' : 'OUT OF SCOPE'}: {scopeTestResult.reason}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {/* FINDING DETAIL DRAWER / MODAL */}
      {activeFinding && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-[#0b101e] border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-950">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    SEVERITY_CONFIG[(activeFinding.finding?.severity || 'info').toLowerCase()]?.badge
                  }`}>
                    {activeFinding.finding?.severity}
                  </span>
                  <span className="font-mono text-xs text-slate-400">{activeFinding.finding?.id}</span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">{activeFinding.finding?.title}</h3>
                <p className="text-xs font-mono text-cyan-400 mt-0.5">
                  {activeFinding.finding?.target}{activeFinding.finding?.path}
                </p>
              </div>
              <button 
                onClick={() => setActiveFinding(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
              {/* Gate Status Card */}
              <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">7-Check Gate Status</h4>
                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-400">
                    {activeFinding.status}
                  </span>
                </div>
                
                {/* Gate Results */}
                <div className="space-y-1.5">
                  {(activeFinding.gate_results || []).map((gr, idx) => (
                    <div key={idx} className="flex items-center justify-between py-1 px-2.5 rounded bg-slate-950/80 border border-slate-800/80">
                      <span className="text-slate-300">Gate {gr.gate_id}: {gr.name}</span>
                      <span className={`flex items-center gap-1 font-mono text-[10px] ${gr.passed ? 'text-emerald-400' : 'text-red-400'}`}>
                        {gr.passed ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {gr.passed ? 'Passed' : gr.reason || 'Failed'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Impact & Remediation */}
              {activeFinding.finding?.impact && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Security Impact & CWE</h4>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-200">
                    {activeFinding.finding.impact}
                  </div>
                </div>
              )}

              {activeFinding.finding?.remediation && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Remediation Instructions</h4>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-200">
                    {activeFinding.finding.remediation}
                  </div>
                </div>
              )}

              {/* Redacted Evidence Bundle */}
              {activeFinding.finding?.evidence && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Matched Evidence</h4>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-amber-300 whitespace-pre-wrap">
                    {activeFinding.finding.evidence}
                  </pre>
                </div>
              )}

              {/* Request & Response */}
              {activeFinding.finding?.request && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">HTTP Request (Redacted)</h4>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 whitespace-pre-wrap overflow-x-auto">
                    {activeFinding.finding.request}
                  </pre>
                </div>
              )}

              {activeFinding.finding?.response && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">HTTP Response Excerpt</h4>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">
                    {activeFinding.finding.response}
                  </pre>
                </div>
              )}

              {/* References */}
              {activeFinding.finding?.references && activeFinding.finding.references.length > 0 && (
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Authoritative References</h4>
                  <ul className="list-disc pl-4 space-y-1 text-cyan-400">
                    {activeFinding.finding.references.map((r, idx) => (
                      <li key={idx}>
                        <a href={r} target="_blank" rel="noreferrer" className="hover:underline break-all">
                          {r}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
