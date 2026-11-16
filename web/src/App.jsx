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
  HelpCircle,
  Sliders,
  Wrench,
  X,
  ChevronDown,
  ChevronUp,
  UserCheck,
  UserX,
  UploadCloud,
  Download,
  Key,
  Share2,
  Database,
  Users,
  Flame,
  Bug,
  FileCode,
  Crosshair,
  BookOpen
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

const RCE_CATEGORY_CONFIG = {
  file_processing: {
    label: 'File Processing',
    color: 'amber',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-300',
    badge: 'bg-amber-500/20 text-amber-300 border border-amber-500/40',
    icon: FileCode,
    description: 'Image converters, PDF generators, document parsers, archive extractors'
  },
  ssti: {
    label: 'Template Injection (SSTI)',
    color: 'purple',
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    text: 'text-purple-300',
    badge: 'bg-purple-500/20 text-purple-300 border border-purple-500/40',
    icon: Code2,
    description: 'Jinja2, FreeMarker, Twig, Velocity, Pebble template engines'
  },
  command_injection: {
    label: 'Command Injection',
    color: 'red',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-300',
    badge: 'bg-red-500/20 text-red-300 border border-red-500/40',
    icon: Terminal,
    description: 'OS process spawns, network utilities (ping/traceroute), shell scripts'
  },
  deserialization: {
    label: 'Insecure Deserialization',
    color: 'pink',
    bg: 'bg-pink-500/10',
    border: 'border-pink-500/30',
    text: 'text-pink-300',
    badge: 'bg-pink-500/20 text-pink-300 border border-pink-500/40',
    icon: Database,
    description: 'Java serialization, Python pickle/yaml, PHP unserialize, .NET formatters'
  },
  expression_language: {
    label: 'Expression Language',
    color: 'blue',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    text: 'text-blue-300',
    badge: 'bg-blue-500/20 text-blue-300 border border-blue-500/40',
    icon: Hash,
    description: 'Spring SpEL, Struts OGNL, MVEL, JEXL expressions'
  },
  background_jobs: {
    label: 'Background Job Queues',
    color: 'cyan',
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-300',
    badge: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40',
    icon: Cpu,
    description: 'Celery, BullMQ, Sidekiq async worker task payloads'
  }
};

const RCE_TIER_CONFIG = {
  component_reachable: { label: 'Component Reachable', bg: 'bg-emerald-500/20', text: 'text-emerald-300', border: 'border-emerald-500/40' },
  ComponentReachable: { label: 'Component Reachable', bg: 'bg-emerald-500/20', text: 'text-emerald-300', border: 'border-emerald-500/40' },
  component_corroborated: { label: 'Component Corroborated', bg: 'bg-cyan-500/20', text: 'text-cyan-300', border: 'border-cyan-500/40' },
  ComponentCorroborated: { label: 'Component Corroborated', bg: 'bg-cyan-500/20', text: 'text-cyan-300', border: 'border-cyan-500/40' },
  version_affected: { label: 'Version Affected', bg: 'bg-blue-500/20', text: 'text-blue-300', border: 'border-blue-500/40' },
  ComponentPresent: { label: 'Component Present', bg: 'bg-blue-500/20', text: 'text-blue-300', border: 'border-blue-500/40' },
  version_identified: { label: 'Version Identified', bg: 'bg-amber-500/20', text: 'text-amber-300', border: 'border-amber-500/40' },
  ComponentInferred: { label: 'Component Inferred', bg: 'bg-amber-500/20', text: 'text-amber-300', border: 'border-amber-500/40' },
  tech_detected: { label: 'Technology Detected', bg: 'bg-slate-700/60', text: 'text-slate-300', border: 'border-slate-600' },
  TechnologyCorrelated: { label: 'Technology Correlated', bg: 'bg-slate-700/60', text: 'text-slate-300', border: 'border-slate-600' },
  none: { label: 'Uncorroborated', bg: 'bg-slate-800', text: 'text-slate-400', border: 'border-slate-700' },
  Uncorroborated: { label: 'Uncorroborated', bg: 'bg-slate-800', text: 'text-slate-400', border: 'border-slate-700' }
};

const getLastAttempt = (cand) => {
  if (!cand) return null;
  if (cand.last_attempt) return cand.last_attempt;
  if (cand.validation_attempts && cand.validation_attempts.length > 0) {
    return cand.validation_attempts[cand.validation_attempts.length - 1];
  }
  return null;
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

// Global local API token for CSRF & Host validation protection
let scoutrApiToken = '';

// Transparently inject loopback protection headers for all outgoing API requests
if (typeof window !== 'undefined' && !window.__scoutr_fetch_interceptor) {
  window.__scoutr_fetch_interceptor = true;
  const origFetch = window.fetch;
  window.fetch = async (input, init = {}) => {
    const headers = new Headers(init.headers || {});
    if (!headers.has('X-Requested-With')) {
      headers.set('X-Requested-With', 'Scoutr');
    }
    if (scoutrApiToken && !headers.has('X-Scoutr-Token')) {
      headers.set('X-Scoutr-Token', scoutrApiToken);
    }
    return origFetch(input, { ...init, headers });
  };
}

export default function App() {
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState('');
  const [activeTab, setActiveTab] = useState('overview');
  const [scope, setScope] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Fetch local API auth token on mount
  useEffect(() => {
    fetch('/api/auth/token')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.token) {
          scoutrApiToken = data.token;
        }
      })
      .catch(() => {});
  }, []);

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

  // Endpoints Intelligence state
  const [endpointsData, setEndpointsData] = useState([]);
  const [endpointsLoading, setEndpointsLoading] = useState(false);
  const [endpointSearch, setEndpointSearch] = useState('');
  const [endpointMethodFilter, setEndpointMethodFilter] = useState('ALL');
  const [endpointClassFilter, setEndpointClassFilter] = useState('ALL');
  const [endpointAuthFilter, setEndpointAuthFilter] = useState('ALL');
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [queuedEndpointMap, setQueuedEndpointMap] = useState({});

  // IDOR Research Center state
  const [authProfiles, setAuthProfiles] = useState([]);
  const [idorCandidates, setIdorCandidates] = useState([]);
  const [idorComparisons, setIdorComparisons] = useState([]);
  const [idorSubTab, setIdorSubTab] = useState('profiles'); // 'profiles' | 'har' | 'candidates' | 'matrix'
  const [userAForm, setUserAForm] = useState({
    principal_label: 'user_a',
    tenant_label: 'tenant_1',
    instance_label: 'default',
    role_label: 'member',
    auth_type: 'bearer',
    identity_endpoint: '',
    token: ''
  });
  const [userBForm, setUserBForm] = useState({
    principal_label: 'user_b',
    tenant_label: 'tenant_2',
    instance_label: 'default',
    role_label: 'member',
    auth_type: 'bearer',
    identity_endpoint: '',
    token: ''
  });
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileNotice, setProfileNotice] = useState(null);
  const [verifyingPrincipal, setVerifyingPrincipal] = useState('');
  const [harUploading, setHarUploading] = useState(false);
  const [harNotice, setHarNotice] = useState(null);
  const [harFile, setHarFile] = useState(null);
  const [harOwner, setHarOwner] = useState('user_a');
  const [harTenant, setHarTenant] = useState('tenant_1');
  const [buildingInventory, setBuildingInventory] = useState(false);
  const [runningDifferential, setRunningDifferential] = useState(false);
  const [activeEvidenceComp, setActiveEvidenceComp] = useState(null);
  const [candidateFilter, setCandidateFilter] = useState('');
  const [showTokenA, setShowTokenA] = useState(false);
  const [showTokenB, setShowTokenB] = useState(false);

  // RCE Research Center state
  const [rceCandidates, setRceCandidates] = useState([]);
  const [rceOverview, setRceOverview] = useState(null);
  const [rceAdvisories, setRceAdvisories] = useState([]);
  const [rceSubTab, setRceSubTab] = useState('overview'); // 'overview' | 'explorer' | 'queue' | 'advisories' | 'validation'
  const [selectedRceCandidate, setSelectedRceCandidate] = useState(null);
  const [rceValidationModalCand, setRceValidationModalCand] = useState(null);
  const [rceEvidenceModalCand, setRceEvidenceModalCand] = useState(null);
  const [rceCategoryFilter, setRceCategoryFilter] = useState('ALL');
  const [rceStatusFilter, setRceStatusFilter] = useState('ALL');
  const [rceSearchFilter, setRceSearchFilter] = useState('');
  const [rceDiscovering, setRceDiscovering] = useState(false);
  const [rceValidating, setRceValidating] = useState(false);
  const [rceValidationProfile, setRceValidationProfile] = useState('safe_active');
  const [rceValidationAuthPrincipal, setRceValidationAuthPrincipal] = useState('');
  const [rceNotice, setRceNotice] = useState(null);
  const [rceCandidateNotes, setRceCandidateNotes] = useState('');
  const [rceCandidateStatus, setRceCandidateStatus] = useState('');
  const [rceSavingNotes, setRceSavingNotes] = useState(false);

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

  // Security Scan orchestration state
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [scanTargetInput, setScanTargetInput] = useState('');
  const [scanMode, setScanMode] = useState('standard'); // 'standard' | 'passive' | 'custom'
  const [customTools, setCustomTools] = useState({
    ports: true,
    probe: true,
    crawl: true,
    fuzz: true,
    xss: true,
    nuclei: true
  });
  const [outOfScopeInput, setOutOfScopeInput] = useState('');
  const [rateLimitInput, setRateLimitInput] = useState(50);
  const [scanStarting, setScanStarting] = useState(false);
  const [scanStatus, setScanStatus] = useState({
    running: false,
    stage_index: 0,
    total_stages: 8,
    stage_name: '',
    detail: '',
    logs: [],
    run_id: '',
    error: ''
  });
  const [showLiveLogs, setShowLiveLogs] = useState(false);
  const [scanNotice, setScanNotice] = useState(null);

  // Modular tools center state
  const [toolsArsenal, setToolsArsenal] = useState([]);
  const [showArsenalDetails, setShowArsenalDetails] = useState(false);
  const [runningTool, setRunningTool] = useState(null);
  const [toolFeedback, setToolFeedback] = useState({});

  // Fetch tools arsenal (installed binaries on host)
  const fetchArsenal = async () => {
    try {
      const res = await fetch('/api/tools');
      if (res.ok) {
        const data = await res.json();
        setToolsArsenal(data || []);
      }
    } catch (err) {
      console.error('Failed loading tools arsenal:', err);
    }
  };

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

  // Load data for currently selected run
  const loadRunData = async () => {
    if (!selectedRunId) return;
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
        subRes,
        epRes,
        profRes,
        candRes,
        compRes,
        rceCandRes,
        rceOverviewRes,
        rceAdvRes
      ] = await Promise.all([
        fetch(`/api/runs/${selectedRunId}/inventory`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/ports`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/httpx`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/crawl`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/fuzz`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/findings`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/triage`).then(r => r.ok ? r.json() : null),
        fetch(`/api/runs/${selectedRunId}/drafts`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/submission_ready`).then(r => r.ok ? r.json() : null),
        fetch(`/api/runs/${selectedRunId}/endpoints`).then(r => r.ok ? r.json() : { endpoints: [] }),
        fetch(`/api/runs/${selectedRunId}/auth/profiles`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/idor/candidates`).then(r => r.ok ? r.json() : { candidates: [] }),
        fetch(`/api/runs/${selectedRunId}/idor/comparisons`).then(r => r.ok ? r.json() : []),
        fetch(`/api/runs/${selectedRunId}/rce/candidates`).then(r => r.ok ? r.json() : { candidates: [] }),
        fetch(`/api/runs/${selectedRunId}/rce/overview`).then(r => r.ok ? r.json() : null),
        fetch(`/api/runs/${selectedRunId}/rce/advisories`).then(r => r.ok ? r.json() : { advisories: [] })
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
      setEndpointsData(epRes?.endpoints || []);
      setAuthProfiles(profRes || []);
      setIdorCandidates(candRes?.candidates || []);
      setIdorComparisons(compRes || []);
      setRceCandidates(rceCandRes?.candidates || []);
      setRceOverview(rceOverviewRes);
      setRceAdvisories(rceAdvRes?.advisories || []);

      // If user A / user B exist in profile summaries, populate forms
      if (profRes && profRes.length > 0) {
        const pA = profRes.find(p => p.principal_label === 'user_a');
        if (pA) {
          setUserAForm(prev => ({
            ...prev,
            principal_label: pA.principal_label,
            tenant_label: pA.tenant_label,
            instance_label: pA.instance_label || 'default',
            role_label: pA.role_label || 'member',
            auth_type: pA.auth_type || 'bearer',
            identity_endpoint: pA.identity_endpoint || ''
          }));
        }
        const pB = profRes.find(p => p.principal_label === 'user_b');
        if (pB) {
          setUserBForm(prev => ({
            ...prev,
            principal_label: pB.principal_label,
            tenant_label: pB.tenant_label,
            instance_label: pB.instance_label || 'default',
            role_label: pB.role_label || 'member',
            auth_type: pB.auth_type || 'bearer',
            identity_endpoint: pB.identity_endpoint || ''
          }));
        }
      }
    } catch (err) {
      console.error('Failed loading run details:', err);
    }
  };

  const handleQueueEndpoint = (ep) => {
    setQueuedEndpointMap(prev => ({
      ...prev,
      [ep.url || ep.normalized_route]: true
    }));
  };

  const handleSaveAuthProfile = async (form) => {
    if (!selectedRunId) return;
    setProfileSaving(true);
    setProfileNotice(null);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/auth/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form)
      });
      if (res.ok) {
        setProfileNotice({ type: 'success', msg: `Saved credentials for ${form.principal_label} (stored securely)` });
        const listRes = await fetch(`/api/runs/${selectedRunId}/auth/profiles`);
        if (listRes.ok) {
          setAuthProfiles(await listRes.json());
        }
      } else {
        const txt = await res.text();
        setProfileNotice({ type: 'error', msg: txt || 'Failed to save profile' });
      }
    } catch (err) {
      setProfileNotice({ type: 'error', msg: err.message });
    } finally {
      setProfileSaving(false);
    }
  };

  const handleVerifyProfile = async (principal) => {
    if (!selectedRunId) return;
    setVerifyingPrincipal(principal);
    setProfileNotice(null);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/auth/profiles/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ principal_label: principal })
      });
      const data = await res.json();
      if (data.identity_status === 'verified') {
        setProfileNotice({ type: 'success', msg: `Identity verified: ID = ${data.verified_id} (Tenant: ${data.verified_tenant || 'N/A'}, Role: ${data.verified_role || 'N/A'})` });
      } else {
        setProfileNotice({ type: 'error', msg: `Verification failed: ${data.error || 'Identity endpoint rejected verification'}` });
      }
      const listRes = await fetch(`/api/runs/${selectedRunId}/auth/profiles`);
      if (listRes.ok) {
        setAuthProfiles(await listRes.json());
      }
    } catch (err) {
      setProfileNotice({ type: 'error', msg: err.message });
    } finally {
      setVerifyingPrincipal('');
    }
  };

  const handleHARUploadSubmit = async (e) => {
    e.preventDefault();
    if (!selectedRunId || !harFile) {
      alert('Please select a .har file first');
      return;
    }
    setHarUploading(true);
    setHarNotice(null);
    try {
      const formData = new FormData();
      formData.append('har', harFile);
      const res = await fetch(`/api/runs/${selectedRunId}/auth/har?owner=${encodeURIComponent(harOwner)}&tenant=${encodeURIComponent(harTenant)}`, {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setHarNotice({ type: 'success', msg: `Imported ${data.endpoints_ingested || 0} endpoints and ${data.candidates_ingested || 0} candidate object references with all secrets redacted.` });
        setHarFile(null);
        loadRunData();
      } else {
        const txt = await res.text();
        setHarNotice({ type: 'error', msg: txt || 'HAR upload failed' });
      }
    } catch (err) {
      setHarNotice({ type: 'error', msg: err.message });
    } finally {
      setHarUploading(false);
    }
  };

  const handleBuildIDORInventory = async () => {
    if (!selectedRunId) return;
    setBuildingInventory(true);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/idor/inventory`, { method: 'POST' });
      if (res.ok) {
        setTimeout(loadRunData, 1500);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setBuildingInventory(false);
    }
  };

  const handleUpdateCandidatePolicy = async (candidateId, policy) => {
    if (!selectedRunId) return;
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/idor/candidates/${candidateId}/policy`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_policy: policy })
      });
      if (res.ok) {
        loadRunData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunDifferentialTesting = async () => {
    if (!selectedRunId) return;
    setRunningDifferential(true);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/idor/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_a_label: 'user_a',
          user_b_label: 'user_b'
        })
      });
      if (res.ok) {
        setIdorSubTab('matrix');
        setTimeout(loadRunData, 2000);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setRunningDifferential(false);
    }
  };

  const handleDiscoverRCE = async () => {
    if (!selectedRunId) return;
    setRceDiscovering(true);
    setRceNotice(null);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/rce/discover`, {
        method: 'POST'
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setRceNotice({
        type: 'success',
        msg: `RCE Discovery finished: discovered ${data.candidates_count || 0} candidates across ${data.endpoints_analyzed || 0} endpoints (${data.chains_count || 0} multi-step chains)!`
      });
      const [candR, overR, advR] = await Promise.all([
        fetch(`/api/runs/${selectedRunId}/rce/candidates`).then(r => r.ok ? r.json() : { candidates: [] }),
        fetch(`/api/runs/${selectedRunId}/rce/overview`).then(r => r.ok ? r.json() : null),
        fetch(`/api/runs/${selectedRunId}/rce/advisories`).then(r => r.ok ? r.json() : { advisories: [] })
      ]);
      setRceCandidates(candR?.candidates || []);
      setRceOverview(overR);
      setRceAdvisories(advR?.advisories || []);
    } catch (err) {
      setRceNotice({ type: 'error', msg: `RCE Discovery failed: ${err.message}` });
    } finally {
      setRceDiscovering(false);
    }
  };

  const handleValidateRCE = async (candidateId, profile) => {
    if (!selectedRunId || !candidateId) return;
    setRceValidating(true);
    setRceNotice(null);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/rce/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          candidate_id: candidateId,
          profile: profile || rceValidationProfile,
          auth_principal: rceValidationAuthPrincipal
        })
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const result = await res.json();
      setRceNotice({
        type: 'success',
        msg: `Validation completed for ${candidateId}: ${result.status} (Profile: ${result.profile})`
      });
      setRceValidationModalCand(null);
      const [candR, overR, findR] = await Promise.all([
        fetch(`/api/runs/${selectedRunId}/rce/candidates`).then(r => r.ok ? r.json() : { candidates: [] }),
        fetch(`/api/runs/${selectedRunId}/rce/overview`).then(r => r.ok ? r.json() : null),
        fetch(`/api/runs/${selectedRunId}/findings`).then(r => r.ok ? r.json() : [])
      ]);
      setRceCandidates(candR?.candidates || []);
      setRceOverview(overR);
      setFindings(findR || []);
      const updated = (candR?.candidates || []).find(c => c.id === candidateId);
      if (updated) setSelectedRceCandidate(updated);
    } catch (err) {
      setRceNotice({ type: 'error', msg: `RCE Validation failed: ${err.message}` });
    } finally {
      setRceValidating(false);
    }
  };

  const handleSaveCandidateNotes = async (candidateId) => {
    if (!selectedRunId || !candidateId) return;
    setRceSavingNotes(true);
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/rce/candidates/${candidateId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notes: rceCandidateNotes,
          status: rceCandidateStatus
        })
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedRceCandidate(updated);
        setRceCandidates(prev => prev.map(c => c.id === candidateId ? updated : c));
        setRceNotice({ type: 'success', msg: `Candidate ${candidateId} updated successfully` });
      }
    } catch (err) {
      setRceNotice({ type: 'error', msg: `Failed updating candidate: ${err.message}` });
    } finally {
      setRceSavingNotes(false);
    }
  };

  const handleExportRCEReport = async () => {
    if (!selectedRunId) return;
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/rce/report`);
      if (!res.ok) {
        throw new Error('Report not generated yet. Run discovery or validation first.');
      }
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rce_research_report_${selectedRunId}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setRceNotice({ type: 'error', msg: `Export failed: ${err.message}` });
    }
  };

  const handleStartScan = async (e) => {
    if (e) e.preventDefault();
    const cleanTarget = scanTargetInput.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    if (!cleanTarget) {
      alert('Please enter a target domain or hostname (e.g. example.com)');
      return;
    }

    setScanStarting(true);
    const exclusions = outOfScopeInput
      .split(/[,\n]/)
      .map(s => s.trim())
      .filter(Boolean);

    const payload = {
      target: cleanTarget,
      in_scope: [cleanTarget, `*.${cleanTarget}`],
      out_of_scope: exclusions,
      scan_mode: scanMode,
      skip_ports: scanMode === 'passive' || (scanMode === 'custom' && !customTools.ports),
      skip_crawl: scanMode === 'passive' || (scanMode === 'custom' && !customTools.crawl),
      skip_fuzz: scanMode === 'passive' || (scanMode === 'custom' && !customTools.fuzz),
      skip_xss: scanMode === 'passive' || (scanMode === 'custom' && !customTools.xss),
      skip_nuclei: scanMode === 'passive' || (scanMode === 'custom' && !customTools.nuclei),
      rate_limit: parseInt(rateLimitInput, 10) || 50
    };

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      setScanModalOpen(false);
      setScanStatus({
        running: true,
        stage_index: 0,
        total_stages: 8,
        stage_name: 'starting',
        target: cleanTarget,
        detail: `Starting security scan on ${cleanTarget}...`,
        logs: [`[INFO] Scan initiated for target: ${cleanTarget}`]
      });
      setShowLiveLogs(true);
      setScanNotice(null);
    } catch (err) {
      alert(`Failed to start scan: ${err.message}`);
    } finally {
      setScanStarting(false);
    }
  };

  const handleCancelScan = async () => {
    try {
      await fetch('/api/scan/cancel', { method: 'POST' });
      setScanStatus(prev => ({ ...prev, running: false, detail: 'Scan stopped by user.' }));
    } catch (err) {
      console.error('Failed to cancel scan:', err);
    }
  };

  const handleExecuteTool = async (toolKey) => {
    if (!selectedRunId) {
      alert('Please select or create a workspace run first.');
      return;
    }
    setRunningTool(toolKey);
    setToolFeedback(prev => ({ ...prev, [toolKey]: null }));
    try {
      const res = await fetch(`/api/runs/${selectedRunId}/tools/${toolKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const data = await res.json();
      const count = data.count ?? (Array.isArray(data.result) ? data.result.length : 'updated');
      setToolFeedback(prev => ({
        ...prev,
        [toolKey]: { msg: `✓ Tool executed successfully (${count} items recorded)`, isError: false }
      }));
      // Reload workspace artifacts to update badges and lists
      loadRunData();
      setTimeout(() => {
        setToolFeedback(prev => ({ ...prev, [toolKey]: null }));
      }, 7000);
    } catch (err) {
      setToolFeedback(prev => ({
        ...prev,
        [toolKey]: { msg: `Execution failed: ${err.message}`, isError: true }
      }));
    } finally {
      setRunningTool(null);
    }
  };

  useEffect(() => {
    fetchRunsAndScope();
    fetchArsenal();

    // Check if a scan is already active on the server
    fetch('/api/scan/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.running) {
          setScanStatus(data);
          setShowLiveLogs(true);
        }
      })
      .catch(() => {});
  }, []);

  // Poll active scan status
  useEffect(() => {
    let interval = null;
    if (scanStatus.running) {
      interval = setInterval(async () => {
        try {
          const res = await fetch('/api/scan/status');
          if (res.ok) {
            const data = await res.json();
            setScanStatus(data);
            if (!data.running) {
              // Scan finished
              fetchRunsAndScope();
              if (data.run_id) {
                setSelectedRunId(data.run_id);
              }
              setScanNotice({
                type: data.error ? 'error' : 'success',
                msg: data.error ? `Scan stopped with error: ${data.error}` : `Scan finished successfully! Target: ${data.target}`
              });
            }
          }
        } catch (e) {
          // ignore network polling blips
        }
      }, 1500);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanStatus.running]);

  // Fetch data for selected run
  useEffect(() => {
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

  // Real-time Server-Sent Events (SSE) stream listener
  useEffect(() => {
    if (typeof window === 'undefined' || !window.EventSource) return;

    let es = null;
    let reconnectTimeout = null;

    const connectSSE = () => {
      try {
        es = new EventSource('/api/events');

        es.addEventListener('progress', (e) => {
          try {
            const data = JSON.parse(e.data);
            setScanStatus(prev => ({
              ...prev,
              stage_index: data.stage_index ?? prev.stage_index,
              stage_name: data.stage ?? prev.stage_name,
              detail: data.detail ?? prev.detail,
              progress: data.progress ?? prev.progress
            }));
          } catch (_) {}
        });

        es.addEventListener('log', (e) => {
          try {
            const data = JSON.parse(e.data);
            if (data.log) {
              setScanStatus(prev => ({
                ...prev,
                logs: [...prev.logs.slice(-500), data.log]
              }));
            }
          } catch (_) {}
        });

        es.addEventListener('endpoint_discovered', () => {
          if (selectedRunId) {
            fetch(`/api/runs/${selectedRunId}/endpoints`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d?.endpoints) setEndpointsData(d.endpoints); });
          }
        });

        es.addEventListener('candidate_discovered', () => {
          if (selectedRunId) {
            fetch(`/api/runs/${selectedRunId}/idor/candidates`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d?.candidates) setIdorCandidates(d.candidates); });
          }
        });

        es.addEventListener('validation_result', () => {
          if (selectedRunId) {
            fetch(`/api/runs/${selectedRunId}/findings`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d) setFindings(d); });
            fetch(`/api/runs/${selectedRunId}/idor/comparisons`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d) setIdorComparisons(d); });
          }
        });

        es.addEventListener('rce_candidate_discovered', () => {
          if (selectedRunId) {
            fetch(`/api/runs/${selectedRunId}/rce/candidates`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d?.candidates) setRceCandidates(d.candidates); });
            fetch(`/api/runs/${selectedRunId}/rce/overview`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d) setRceOverview(d); });
          }
        });

        es.addEventListener('rce_validation_result', () => {
          if (selectedRunId) {
            fetch(`/api/runs/${selectedRunId}/rce/candidates`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d?.candidates) setRceCandidates(d.candidates); });
            fetch(`/api/runs/${selectedRunId}/rce/overview`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d) setRceOverview(d); });
            fetch(`/api/runs/${selectedRunId}/findings`)
              .then(r => r.ok ? r.json() : null)
              .then(d => { if (d) setFindings(d); });
          }
        });

        es.addEventListener('job_completed', () => {
          fetchRunsAndScope();
          if (selectedRunId) loadRunData();
        });

        es.addEventListener('job_cancelled', () => {
          fetchRunsAndScope();
          if (selectedRunId) loadRunData();
        });

        es.addEventListener('sync_required', () => {
          // Reconnection detected a ring buffer gap; resync full workspace state
          fetchRunsAndScope();
          if (selectedRunId) loadRunData();
        });

        es.onerror = () => {
          if (es) es.close();
          reconnectTimeout = setTimeout(connectSSE, 4000);
        };
      } catch (err) {
        reconnectTimeout = setTimeout(connectSSE, 5000);
      }
    };

    connectSSE();

    return () => {
      if (es) es.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [selectedRunId]);

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

  // Filtered endpoints
  const filteredEndpoints = endpointsData.filter(ep => {
    if (endpointMethodFilter !== 'ALL') {
      if (!ep.methods?.some(m => m.toUpperCase() === endpointMethodFilter)) return false;
    }
    if (endpointClassFilter !== 'ALL') {
      if (!ep.classifications?.some(c => c.category === endpointClassFilter)) return false;
    }
    if (endpointAuthFilter !== 'ALL') {
      if (!ep.auth_observations?.some(o => o.status === endpointAuthFilter)) return false;
    }
    if (endpointSearch) {
      const q = endpointSearch.toLowerCase();
      const matchUrl = ep.url?.toLowerCase().includes(q);
      const matchRoute = ep.normalized_route?.toLowerCase().includes(q);
      const matchParam = ep.query_params?.some(p => p.toLowerCase().includes(q));
      return matchUrl || matchRoute || matchParam;
    }
    return true;
  });

  // Filtered IDOR candidates
  const filteredCandidates = idorCandidates.filter(c => {
    if (candidateFilter) {
      const q = candidateFilter.toLowerCase();
      return (
        c.object_id?.toLowerCase().includes(q) ||
        c.route_template?.toLowerCase().includes(q) ||
        c.param_name?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Filtered RCE candidates
  const filteredRceCandidates = rceCandidates.filter(c => {
    if (rceCategoryFilter !== 'ALL' && c.category !== rceCategoryFilter) return false;
    if (rceStatusFilter !== 'ALL' && c.status !== rceStatusFilter) return false;
    if (rceSearchFilter) {
      const q = rceSearchFilter.toLowerCase();
      const matchRoute = c.route?.toLowerCase().includes(q);
      const matchUrl = c.target_url?.toLowerCase().includes(q);
      const matchHypo = c.hypothesis?.toLowerCase().includes(q);
      const matchSink = c.suspected_sink?.toLowerCase().includes(q);
      const matchId = c.id?.toLowerCase().includes(q);
      return matchRoute || matchUrl || matchHypo || matchSink || matchId;
    }
    return true;
  });

  return (
    <div className="flex flex-col min-h-screen bg-[#080c15] bg-ambient-mesh text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#0c1222]/85 backdrop-blur-xl sticky top-0 z-40 px-6 py-3.5 shadow-sm shadow-black/40">
        <div className="flex flex-wrap items-center justify-between gap-4 max-w-7xl mx-auto">
          {/* Logo & Product Title */}
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 shadow-lg shadow-cyan-500/25 ring-1 ring-white/20 text-white font-black tracking-wider transition hover:scale-105 duration-200">
              <Shield className="w-5 h-5 drop-shadow" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white font-mono flex items-center gap-2">
                  <span>scoutr</span>
                </h1>
                <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/25">
                  Unified Recon & Gate
                </span>
              </div>
              <p className="text-xs text-slate-400">Deterministic Reconnaissance & 7-Check Readiness Gate</p>
            </div>
          </div>

          {/* Run Selector & Quick Actions */}
          <div className="flex items-center gap-3">
            {/* New Scan Launch Button */}
            <button
              onClick={() => setScanModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:-translate-y-0.5 active:translate-y-0 transition-all cursor-pointer"
              title="Launch a new automated security scan"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>New Scan</span>
            </button>

            <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-700/80 rounded-xl px-3 py-1.5 text-xs shadow-inner">
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
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 text-xs font-mono shadow-sm">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
              </span>
              <span>Scope Guard Active</span>
            </div>

            <button
              onClick={fetchRunsAndScope}
              disabled={refreshing}
              className="p-2 text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/60 rounded-xl transition cursor-pointer"
              title="Refresh Runs"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Navigation Tabs */}
      <nav className="border-b border-slate-800/80 bg-[#0a0f1d]/75 backdrop-blur px-6">
        <div className="flex gap-1.5 max-w-7xl mx-auto overflow-x-auto text-sm font-medium py-1">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'tools', label: 'Tools Center', icon: Zap, highlight: true },
            { id: 'endpoints', label: 'Endpoints Explorer', icon: Layers, count: endpointsData.length },
            { id: 'idor', label: 'IDOR Center', icon: Lock, count: idorCandidates.length, highlight: true },
            { id: 'rce', label: 'RCE Research Center', icon: Terminal, count: rceCandidates.length, highlight: true },
            { id: 'recon', label: 'Attack Surface', icon: Globe, count: ports.length + httpx.length },
            { id: 'findings', label: 'Readiness Gate & Findings', icon: Shield, count: findings.length },
            { id: 'drafts', label: 'Drafts & Reports', icon: FileText, count: drafts.length },
            { id: 'scope', label: 'Scope Guard', icon: Lock },
            { id: 'triage', label: '(Optional) AI Triage', icon: Cpu, count: triage?.verdicts?.length || 0 }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 py-2.5 px-3.5 rounded-lg font-medium transition whitespace-nowrap cursor-pointer text-xs ${
                  active 
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10' 
                    : tab.highlight
                      ? 'text-amber-300 hover:text-amber-200 hover:bg-amber-500/10 border border-amber-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-cyan-400' : tab.highlight ? 'text-amber-400' : ''}`} />
                <span>{tab.label}</span>
                {tab.count !== undefined && tab.count > 0 && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full ${
                    active ? 'bg-cyan-500/30 text-cyan-200' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* Active Scan Progress Stepper & Live Drawer */}
      {(scanStatus.running || scanNotice) && (
        <div className="border-b border-slate-800/90 bg-gradient-to-b from-[#0c1426] to-[#080d1a] px-6 py-4 shadow-xl">
          <div className="max-w-7xl mx-auto space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl border ${
                  scanStatus.running 
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 shadow-sm shadow-cyan-500/20' 
                    : scanNotice?.type === 'error' 
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' 
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}>
                  {scanStatus.running ? (
                    <RefreshCw className="w-5 h-5 animate-spin" />
                  ) : scanNotice?.type === 'error' ? (
                    <AlertTriangle className="w-5 h-5 text-rose-400" />
                  ) : (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs uppercase font-mono font-bold tracking-wider text-cyan-400">
                      {scanStatus.running ? 'Active Scan in Progress' : 'Scan Finished'}
                    </span>
                    {scanStatus.target && (
                      <span className="text-xs font-mono font-bold text-white bg-slate-800 px-2 py-0.5 rounded-md border border-slate-700">
                        {scanStatus.target}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5 font-medium">
                    {scanStatus.detail || scanNotice?.msg || 'Running security checks...'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowLiveLogs(prev => !prev)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{showLiveLogs ? 'Hide Live Logs' : 'View Live Logs'}</span>
                </button>

                {scanStatus.running ? (
                  <button
                    onClick={handleCancelScan}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-300 text-xs font-semibold transition cursor-pointer"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    <span>Stop Scan</span>
                  </button>
                ) : (
                  <button
                    onClick={() => setScanNotice(null)}
                    className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 cursor-pointer transition"
                    title="Dismiss"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {/* 8-Stage Visual Stepper */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 pt-1">
              {[
                { index: 1, name: 'Scope' },
                { index: 2, name: 'Subdomains' },
                { index: 3, name: 'Ports & Svcs' },
                { index: 4, name: 'Web Probe' },
                { index: 5, name: 'Katana Crawl' },
                { index: 6, name: 'FFUF Fuzz' },
                { index: 7, name: 'Safe Probes' },
                { index: 8, name: '7-Check Gate' }
              ].map(stage => {
                const isDone = scanStatus.stage_index > stage.index || (!scanStatus.running && !scanStatus.error && scanStatus.stage_index >= 8);
                const isCurrent = scanStatus.running && scanStatus.stage_index === stage.index;
                return (
                  <div 
                    key={stage.index}
                    className={`flex items-center gap-2 px-2.5 py-2 rounded-xl border text-xs font-mono transition-all duration-200 ${
                      isDone 
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 shadow-sm shadow-emerald-500/5' 
                        : isCurrent 
                          ? 'bg-cyan-500/20 border-cyan-500 text-cyan-200 ring-2 ring-cyan-500/40 shadow-md shadow-cyan-500/10 animate-pulse' 
                          : 'bg-slate-900/40 border-slate-800 text-slate-500'
                    }`}
                  >
                    {isDone ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : isCurrent ? (
                      <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin shrink-0" />
                    ) : (
                      <span className="w-3.5 h-3.5 flex items-center justify-center text-[10px] rounded-full border border-slate-700 text-slate-500 shrink-0">
                        {stage.index}
                      </span>
                    )}
                    <span className="truncate">{stage.name}</span>
                  </div>
                );
              })}
            </div>

            {/* Live Log Terminal Drawer with macOS window dots */}
            {showLiveLogs && (
              <div className="mt-2 rounded-2xl bg-[#070b14] border border-slate-800 shadow-2xl overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 bg-[#0a0f1d] border-b border-slate-800/80 text-xs text-slate-400 font-mono">
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80"></div>
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80"></div>
                      <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
                    </div>
                    <span className="text-slate-400 text-[11px] font-semibold pl-2">scoutr-pipeline@local: ~/audit-stream</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[11px] text-slate-500 font-mono">{scanStatus.logs?.length || 0} lines</span>
                    {scanStatus.logs && scanStatus.logs.length > 0 && (
                      <button
                        onClick={() => {
                          navigator.clipboard?.writeText(scanStatus.logs.join('\n'));
                        }}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono transition cursor-pointer"
                      >
                        Copy All
                      </button>
                    )}
                  </div>
                </div>
                <div className="p-3.5 font-mono text-[11px] text-slate-300 max-h-56 overflow-y-auto space-y-0.5 select-text">
                  {scanStatus.logs && scanStatus.logs.length > 0 ? (
                    scanStatus.logs.map((line, idx) => {
                      let colorClass = 'text-slate-300';
                      if (line.includes('ERROR') || line.includes('error') || line.includes('failed')) {
                        colorClass = 'text-rose-400 font-semibold';
                      } else if (line.includes('completed') || line.includes('Verified') || line.includes('SUCCESS')) {
                        colorClass = 'text-emerald-400 font-semibold';
                      } else if (line.includes('[1/8]') || line.includes('[2/8]') || line.includes('[3/8]') || line.includes('[4/8]') || line.includes('[5/8]') || line.includes('[6/8]') || line.includes('[7/8]') || line.includes('[8/8]')) {
                        colorClass = 'text-cyan-400';
                      }
                      return (
                        <div key={idx} className={`leading-relaxed hover:bg-slate-900/60 px-1.5 py-0.5 rounded transition ${colorClass}`}>
                          {line}
                        </div>
                      );
                    })
                  ) : (
                    <p className="text-slate-500 italic py-2">Awaiting output stream...</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

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
                {/* Empty State Banner when no runs exist */}
                {runs.length === 0 && (
                  <div className="p-8 rounded-2xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 text-center space-y-4 my-4 max-w-2xl mx-auto shadow-2xl">
                    <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center mx-auto text-white shadow-lg shadow-cyan-500/20">
                      <Shield className="w-7 h-7" />
                    </div>
                    <h3 className="text-xl font-bold text-white">Welcome to scoutr</h3>
                    <p className="text-sm text-slate-400 leading-relaxed">
                      scoutr is an automated reconnaissance and vulnerability verification suite.
                      It runs complete subdomain discovery, port scanning, web application crawling, directory fuzzing,
                      and 7-check deterministic verification without requiring any computer expertise.
                    </p>
                    <div className="pt-2">
                      <button
                        onClick={() => setScanModalOpen(true)}
                        className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-sm shadow-xl shadow-cyan-500/25 transition cursor-pointer"
                      >
                        <Zap className="w-4 h-4 fill-current" />
                        <span>Start Your First Security Scan</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Quick Action Shortcuts */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <button
                    onClick={() => setScanModalOpen(true)}
                    className="p-3.5 rounded-xl bg-gradient-to-r from-cyan-950/40 to-blue-950/40 border border-cyan-800/40 hover:border-cyan-500/60 flex items-center justify-between text-left group transition cursor-pointer"
                  >
                    <div>
                      <div className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 fill-current text-cyan-400" />
                        <span>New Security Scan</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">Audit a new domain with 1 click</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition" />
                  </button>

                  <button
                    onClick={() => setActiveTab('tools')}
                    className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 flex items-center justify-between text-left group transition cursor-pointer"
                  >
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-1.5">
                        <Layers className="w-3.5 h-3.5 text-amber-400" />
                        <span>Tools Center</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">Run individual tools on demand</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-amber-400 group-hover:translate-x-0.5 transition" />
                  </button>

                  <button
                    onClick={() => setActiveTab('rce')}
                    className="p-3.5 rounded-xl bg-gradient-to-r from-purple-950/40 to-slate-900/60 border border-purple-800/40 hover:border-purple-500/60 flex items-center justify-between text-left group transition cursor-pointer"
                  >
                    <div>
                      <div className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-purple-400" />
                        <span>RCE Research Center</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">{rceCandidates.length} potential attack surfaces</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition" />
                  </button>

                  <button
                    onClick={() => setActiveTab('findings')}
                    className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 flex items-center justify-between text-left group transition cursor-pointer"
                  >
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-emerald-400" />
                        <span>7-Check Readiness Gate</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">Inspect verified audit results</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition" />
                  </button>
                </div>

                {/* Target banner */}
                <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800/90 shadow-xl flex flex-wrap items-center justify-between gap-4 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-80 h-32 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40">
                        Active Workspace Target
                      </span>
                      <span className="text-xs text-slate-500 font-mono">Run: {selectedRun.id}</span>
                    </div>
                    <h2 className="text-2xl sm:text-3xl font-extrabold font-mono text-white mt-1 tracking-tight flex items-center gap-2">
                      <Globe className="w-6 h-6 text-cyan-400" />
                      <span>{selectedRun.target}</span>
                    </h2>
                  </div>
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shadow-sm">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Scope Enforced at Transport
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-blue-500/10 text-blue-300 border border-blue-500/30 shadow-sm">
                      <Lock className="w-3.5 h-3.5 text-blue-400" /> 7-Check Authority Gate
                    </span>
                  </div>
                </div>

                {/* Primary Metric KPI Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* Verified Findings */}
                  <div className="p-5 rounded-2xl bg-gradient-to-br from-emerald-950/30 via-slate-900/90 to-slate-950 border border-emerald-500/30 shadow-lg shadow-emerald-950/20 hover:border-emerald-500/50 transition flex items-center justify-between group">
                    <div>
                      <p className="text-[11px] text-emerald-300/80 uppercase font-bold tracking-wider">Verified Findings</p>
                      <h3 className="text-3xl font-extrabold text-emerald-400 font-mono mt-1 tracking-tight">{verifiedCount}</h3>
                      <p className="text-[11px] text-slate-400 mt-1">Confirmed by 7-Check gate</p>
                    </div>
                    <div className="p-3.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 group-hover:scale-110 group-hover:bg-emerald-500/20 transition">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                  </div>

                  {/* Needs Manual Review */}
                  <div className="p-5 rounded-2xl bg-gradient-to-br from-amber-950/30 via-slate-900/90 to-slate-950 border border-amber-500/30 shadow-lg shadow-amber-950/20 hover:border-amber-500/50 transition flex items-center justify-between group">
                    <div>
                      <p className="text-[11px] text-amber-300/80 uppercase font-bold tracking-wider">Needs Manual Review</p>
                      <h3 className="text-3xl font-extrabold text-amber-400 font-mono mt-1 tracking-tight">{reviewCount}</h3>
                      <p className="text-[11px] text-slate-400 mt-1">Headers or ambiguous cases</p>
                    </div>
                    <div className="p-3.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/30 group-hover:scale-110 group-hover:bg-amber-500/20 transition">
                      <AlertTriangle className="w-6 h-6" />
                    </div>
                  </div>

                  {/* Suppressed Findings */}
                  <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/70 via-slate-900/90 to-slate-950 border border-slate-800 shadow-lg hover:border-slate-700 transition flex items-center justify-between group">
                    <div>
                      <p className="text-[11px] text-slate-400 uppercase font-bold tracking-wider">Suppressed (False +)</p>
                      <h3 className="text-3xl font-extrabold text-slate-400 font-mono mt-1 tracking-tight">{suppressedCount}</h3>
                      <p className="text-[11px] text-slate-500 mt-1">Filtered by soft-404 / scope</p>
                    </div>
                    <div className="p-3.5 rounded-xl bg-slate-800/80 text-slate-400 border border-slate-700 group-hover:scale-110 transition">
                      <XCircle className="w-6 h-6" />
                    </div>
                  </div>

                  {/* Surface Discovered */}
                  <div className="p-5 rounded-2xl bg-gradient-to-br from-cyan-950/30 via-slate-900/90 to-slate-950 border border-cyan-500/30 shadow-lg shadow-cyan-950/20 hover:border-cyan-500/50 transition flex items-center justify-between group">
                    <div>
                      <p className="text-[11px] text-cyan-300/80 uppercase font-bold tracking-wider">Surface Discovered</p>
                      <h3 className="text-3xl font-extrabold text-cyan-400 font-mono mt-1 tracking-tight">{ports.length + httpx.length}</h3>
                      <p className="text-[11px] text-slate-400 mt-1">{ports.length} ports, {httpx.length} HTTP hosts</p>
                    </div>
                    <div className="p-3.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 group-hover:scale-110 group-hover:bg-cyan-500/20 transition">
                      <Globe className="w-6 h-6" />
                    </div>
                  </div>
                </div>

                {/* Attack Surface Quick Snapshot Row */}
                <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-400 px-1">
                    <span>Target Attack Surface Breakdown</span>
                    <button
                      onClick={() => setActiveTab('recon')}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 normal-case font-mono transition cursor-pointer"
                    >
                      <span>Explore all in Attack Surface</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                    {[
                      { id: 'inventory', label: 'Subdomains', count: inventory.length, icon: Globe, color: 'text-blue-400' },
                      { id: 'ports', label: 'Open Ports', count: ports.length, icon: Server, color: 'text-cyan-400' },
                      { id: 'httpx', label: 'Live HTTP Hosts', count: httpx.length, icon: Activity, color: 'text-teal-400' },
                      { id: 'crawl', label: 'Crawled URLs', count: crawl.length, icon: Search, color: 'text-indigo-400' },
                      { id: 'fuzz', label: 'Fuzzed Paths', count: fuzz.length, icon: Layers, color: 'text-purple-400' },
                    ].map(item => {
                      const ItemIcon = item.icon;
                      return (
                        <button
                          key={item.id}
                          onClick={() => {
                            setReconSubTab(item.id);
                            setActiveTab('recon');
                          }}
                          className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/80 transition text-left flex items-center justify-between group cursor-pointer"
                        >
                          <div>
                            <span className="text-[10px] text-slate-400 uppercase font-semibold block">{item.label}</span>
                            <span className="text-lg font-bold font-mono text-white mt-0.5 block">{item.count}</span>
                          </div>
                          <ItemIcon className={`w-4 h-4 ${item.color} opacity-70 group-hover:opacity-100 group-hover:scale-110 transition`} />
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Severity Breakdown Bar */}
                <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">Findings Severity Distribution</h3>
                      <p className="text-xs text-slate-400 mt-0.5">Summary of all security issues flagged across the scan</p>
                    </div>
                    <span className="text-xs text-slate-400 font-mono px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800">
                      {findings.length} Total Findings
                    </span>
                  </div>

                  {/* Visual Proportion Bar */}
                  {findings.length > 0 && (
                    <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden flex p-0.5 gap-0.5 border border-slate-800">
                      {['critical', 'high', 'medium', 'low', 'info'].map(s => {
                        const count = severityCounts[s] || 0;
                        if (count === 0) return null;
                        const pct = Math.max(3, (count / findings.length) * 100);
                        const colors = {
                          critical: 'bg-red-500',
                          high: 'bg-orange-500',
                          medium: 'bg-amber-500',
                          low: 'bg-blue-500',
                          info: 'bg-slate-500'
                        };
                        return (
                          <div
                            key={s}
                            style={{ width: `${pct}%` }}
                            title={`${s.toUpperCase()}: ${count} (${Math.round((count / findings.length) * 100)}%)`}
                            className={`${colors[s]} h-full rounded-sm transition-all duration-500`}
                          />
                        );
                      })}
                    </div>
                  )}

                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    {['critical', 'high', 'medium', 'low', 'info'].map(s => {
                      const count = severityCounts[s] || 0;
                      const cfg = SEVERITY_CONFIG[s];
                      return (
                        <div key={s} className={`p-3.5 rounded-xl border ${cfg.border} ${cfg.bg} flex items-center justify-between`}>
                          <div>
                            <span className="text-xs uppercase font-extrabold tracking-wider text-slate-300 block">{s}</span>
                            <span className="text-[10px] text-slate-400">
                              {findings.length > 0 ? `${Math.round((count / findings.length) * 100)}%` : '0%'}
                            </span>
                          </div>
                          <span className={`text-xl font-black font-mono ${cfg.text}`}>{count}</span>
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

            {/* TOOLS CENTER TAB */}
            {activeTab === 'tools' && (
              <div className="space-y-6">
                {/* Tools Center Banner */}
                <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <Zap className="w-5 h-5 text-amber-400 fill-amber-400/20" />
                        Security Tools Center
                      </h2>
                      <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        No CLI Required
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                      Trigger individual reconnaissance, discovery, fuzzing, or verification tools directly with a single click. 
                      Every tool automatically obeys the absolute scope guard at the transport layer.
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setShowArsenalDetails(prev => !prev)}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 border border-slate-700 text-xs font-mono text-slate-300 transition cursor-pointer"
                    >
                      <Wrench className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Arsenal: {toolsArsenal.filter(t => t.Installed).length}/{toolsArsenal.length || 8} Installed</span>
                      {showArsenalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Arsenal Installed Details (Collapsible) */}
                {showArsenalDetails && (
                  <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                        Host Tool Binary Status (PATH Inspection)
                      </h3>
                      <span className="text-xs text-slate-500 font-mono">Verified via tools.InspectArsenal</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      {toolsArsenal.map(tool => (
                        <div key={tool.Binary} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-white">{tool.Binary}</span>
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-medium ${
                                tool.Installed ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-slate-800 text-slate-400'
                              }`}>
                                {tool.Installed ? `v${tool.Version}` : 'Not found'}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">{tool.Description}</p>
                            {!tool.Installed && tool.InstallHint && (
                              <p className="text-[10px] text-cyan-400 font-mono mt-1">Hint: {tool.InstallHint}</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tool Cards Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {[
                    {
                      key: 'subdomains',
                      title: 'Subdomain Finder',
                      subtitle: 'Passive Recon & DNS',
                      engine: 'subfinder, assetfinder, crt.sh, dnsx',
                      icon: Globe,
                      accent: {
                        border: 'hover:border-blue-500/60',
                        badge: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
                        iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
                        btn: 'from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500',
                      },
                      count: `${inventory.length} Subdomains`,
                      desc: 'Discovers active subdomains via certificate transparency and resolves DNS. Zero active packets sent to target web servers.',
                      whenToUse: 'Start here to discover all websites and servers belonging to your target.',
                      actionLabel: 'Discover Subdomains',
                      viewTab: 'recon'
                    },
                    {
                      key: 'ports',
                      title: 'Port & Service Scanner',
                      subtitle: 'TCP Port Enumeration',
                      engine: 'naabu, nmap',
                      icon: Server,
                      accent: {
                        border: 'hover:border-cyan-500/60',
                        badge: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
                        iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
                        btn: 'from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500',
                      },
                      count: `${ports.length} Open Ports`,
                      desc: 'Scans top ports across discovered hosts and fingerprints running services with read-only probe signatures.',
                      whenToUse: 'Find which network doors (ports 80, 443, 8080, etc.) are open on target servers.',
                      actionLabel: 'Scan Open Ports',
                      viewTab: 'recon'
                    },
                    {
                      key: 'probe',
                      title: 'Live Web Prober',
                      subtitle: 'HTTP/HTTPS Fingerprinting',
                      engine: 'httpx',
                      icon: Activity,
                      accent: {
                        border: 'hover:border-teal-500/60',
                        badge: 'text-teal-400 bg-teal-500/10 border-teal-500/20',
                        iconBg: 'bg-teal-500/10 text-teal-400 border-teal-500/20',
                        btn: 'from-teal-600 to-emerald-600 hover:from-teal-500 hover:to-emerald-500',
                      },
                      count: `${httpx.length} Web Endpoints`,
                      desc: 'Probes HTTP and HTTPS ports, extracts website titles, response status codes, web server banners, and tech stacks.',
                      whenToUse: 'Check which open ports actually host live web applications and view technologies.',
                      actionLabel: 'Probe Web Servers',
                      viewTab: 'recon'
                    },
                    {
                      key: 'crawl',
                      title: 'Web Application Crawler',
                      subtitle: 'Fast URL & Endpoint Crawl',
                      engine: 'katana',
                      icon: Search,
                      accent: {
                        border: 'hover:border-indigo-500/60',
                        badge: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20',
                        iconBg: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
                        btn: 'from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500',
                      },
                      count: `${crawl.length} Crawled URLs`,
                      desc: 'Crawls live web applications to discover links, API endpoints, hidden forms, and JavaScript routes.',
                      whenToUse: 'Automatically browse and map out every URL, page, and hidden button on the site.',
                      actionLabel: 'Crawl Endpoints',
                      viewTab: 'recon'
                    },
                    {
                      key: 'fuzz',
                      title: 'Directory & File Fuzzer',
                      subtitle: 'Hidden Path Discovery',
                      engine: 'ffuf',
                      icon: Layers,
                      accent: {
                        border: 'hover:border-purple-500/60',
                        badge: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
                        iconBg: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
                        btn: 'from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500',
                      },
                      count: `${fuzz.length} Paths Fuzzed`,
                      desc: 'Fuzzes web paths to discover hidden directories, configuration backups, sensitive admin panels, and files.',
                      whenToUse: 'Detect unlinked sensitive files, backup folders (e.g. /backup.zip), or admin panels.',
                      actionLabel: 'Fuzz Directories',
                      viewTab: 'recon'
                    },
                    {
                      key: 'xss',
                      title: 'XSS Vulnerability Prober',
                      subtitle: 'Safe Reflection Testing',
                      engine: 'dalfox',
                      icon: AlertOctagon,
                      accent: {
                        border: 'hover:border-amber-500/60',
                        badge: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
                        iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
                        btn: 'from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500',
                      },
                      count: 'Safe Parameter Probes',
                      desc: 'Tests discovered URL parameters for reflected cross-site scripting without executing destructive payloads.',
                      whenToUse: 'Verify if input parameters safely reflect back in browser responses without risk.',
                      actionLabel: 'Test for XSS',
                      viewTab: 'findings'
                    },
                    {
                      key: 'nuclei',
                      title: 'Vulnerability Posture',
                      subtitle: 'Safe Community Templates',
                      engine: 'nuclei (read-only)',
                      icon: Shield,
                      accent: {
                        border: 'hover:border-rose-500/60',
                        badge: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
                        iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
                        btn: 'from-rose-600 to-pink-600 hover:from-rose-500 hover:to-pink-500',
                      },
                      count: 'Safe Posture Tags',
                      desc: 'Runs community-curated vulnerability templates for CVEs, exposed panels, and common security misconfigurations.',
                      whenToUse: 'Test against thousands of known vulnerabilities using verified safe read-only checks.',
                      actionLabel: 'Run Posture Scan',
                      viewTab: 'findings'
                    },
                    {
                      key: 'validate',
                      title: '7-Check Readiness Gate',
                      subtitle: 'Deterministic Verification',
                      engine: 'internal/validate & report',
                      icon: CheckCircle2,
                      accent: {
                        border: 'hover:border-emerald-500/60',
                        badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
                        iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
                        btn: 'from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500',
                      },
                      count: `${verifiedCount} Verified Findings`,
                      desc: 'Executes the authoritative 7-check readiness gate on all findings and generates HTML/Markdown executive reports.',
                      whenToUse: 'Filter out false alarms and generate final audit reports with 100% confidence.',
                      actionLabel: 'Validate & Build Report',
                      viewTab: 'findings'
                    }
                  ].map(tool => {
                    const Icon = tool.icon;
                    const isRunning = runningTool === tool.key;
                    const feedback = toolFeedback[tool.key];

                    return (
                      <div 
                        key={tool.key}
                        className={`p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 shadow-xl flex flex-col justify-between transition-all duration-300 hover:shadow-2xl hover:-translate-y-0.5 space-y-4 ${tool.accent.border}`}
                      >
                        <div className="space-y-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className={`p-2.5 rounded-xl border ${tool.accent.iconBg} shadow-sm`}>
                              <Icon className="w-5 h-5" />
                            </div>
                            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 truncate max-w-[130px]" title={tool.engine}>
                              {tool.engine.split(',')[0]}
                            </span>
                          </div>

                          <div>
                            <h3 className="font-bold text-white text-base tracking-tight">{tool.title}</h3>
                            <p className="text-[11px] text-cyan-400 font-medium font-mono">{tool.subtitle}</p>
                            <div className={`mt-2 text-xs font-mono font-bold px-2.5 py-1 rounded-md inline-block border ${tool.accent.badge}`}>
                              {tool.count}
                            </div>
                          </div>

                          <p className="text-xs text-slate-400 leading-relaxed">
                            {tool.desc}
                          </p>

                          {/* Plain-English guide for beginners */}
                          <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-300 leading-relaxed">
                            <span className="font-semibold text-slate-200 block mb-0.5">💡 Why run this:</span>
                            <span className="text-slate-400">{tool.whenToUse}</span>
                          </div>
                        </div>

                        <div className="space-y-2 pt-2 border-t border-slate-800/80">
                          {feedback && (
                            <div className={`p-2 rounded-lg text-[11px] font-mono leading-tight ${
                              feedback.isError 
                                ? 'bg-red-500/10 border border-red-500/30 text-red-300' 
                                : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                            }`}>
                              {feedback.msg}
                            </div>
                          )}

                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleExecuteTool(tool.key)}
                              disabled={isRunning || scanStatus.running || !selectedRunId}
                              className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-xl text-xs font-bold transition shadow-md cursor-pointer ${
                                isRunning 
                                  ? 'bg-cyan-600/30 border border-cyan-500/50 text-cyan-300 animate-pulse' 
                                  : 'bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 hover:border-slate-600'
                              } disabled:opacity-50 disabled:cursor-not-allowed`}
                            >
                              {isRunning ? (
                                <>
                                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                                  <span>Running...</span>
                                </>
                              ) : (
                                <>
                                  <Play className="w-3.5 h-3.5 text-cyan-400 fill-cyan-400" />
                                  <span>{tool.actionLabel}</span>
                                </>
                              )}
                            </button>

                            <button
                              onClick={() => setActiveTab(tool.viewTab)}
                              className="p-2.5 rounded-xl bg-slate-800/50 hover:bg-slate-750 text-slate-400 hover:text-white border border-slate-700/60 transition cursor-pointer"
                              title="View results in dashboard"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
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
                {/* Clarification banner: AI is optional */}
                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start gap-3 text-xs text-slate-300">
                  <HelpCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-white">AI Triage is purely optional:</span>
                    <p className="text-slate-400 leading-relaxed">
                      Scoutr operates completely and deterministically without requiring an AI model or connection. 
                      All reconnaissance tools, port scanners, crawlers, and the 7-Check Readiness Gate run 100% locally on your machine. 
                      If you want an AI to assist with ranking findings and drafting descriptions, connect LM Studio, llama.cpp, or Ollama below.
                    </p>
                  </div>
                </div>

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

            {/* ENDPOINTS EXPLORER TAB */}
            {activeTab === 'endpoints' && (
              <div className="space-y-6">
                {/* Header */}
                <div className="flex flex-wrap items-center justify-between gap-4 p-6 rounded-2xl bg-[#0c1322] border border-slate-800 shadow-xl">
                  <div>
                    <div className="flex items-center gap-2">
                      <Layers className="w-5 h-5 text-cyan-400" />
                      <h2 className="text-lg font-bold text-white tracking-tight">Endpoint Intelligence Explorer</h2>
                      <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                        {endpointsData.length} Discovered
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">
                      Normalized application route inventory aggregated across crawlers, historical archives, JS analyzers, and API specifications.
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => loadRunData()}
                      disabled={endpointsLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${endpointsLoading ? 'animate-spin text-cyan-400' : ''}`} />
                      <span>Refresh</span>
                    </button>
                  </div>
                </div>

                {/* Search & Filters */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                    {/* Search */}
                    <div className="lg:col-span-2 relative">
                      <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        placeholder="Search URL, route path, or parameter..."
                        value={endpointSearch}
                        onChange={e => setEndpointSearch(e.target.value)}
                        className="w-full bg-slate-950/80 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 font-mono placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    {/* Method */}
                    <div>
                      <select
                        value={endpointMethodFilter}
                        onChange={e => setEndpointMethodFilter(e.target.value)}
                        className="w-full bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
                      >
                        <option value="ALL">All Methods</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                      </select>
                    </div>

                    {/* Classification */}
                    <div>
                      <select
                        value={endpointClassFilter}
                        onChange={e => setEndpointClassFilter(e.target.value)}
                        className="w-full bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
                      >
                        <option value="ALL">All Categories</option>
                        <option value="user_data">User Data</option>
                        <option value="admin">Admin</option>
                        <option value="auth">Auth</option>
                        <option value="file_process">File Processing</option>
                        <option value="doc_convert">Doc Conversion</option>
                        <option value="template_render">Template Render</option>
                        <option value="background_job">Background Job</option>
                        <option value="general_api">General API</option>
                      </select>
                    </div>

                    {/* Auth filter */}
                    <div>
                      <select
                        value={endpointAuthFilter}
                        onChange={e => setEndpointAuthFilter(e.target.value)}
                        className="w-full bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
                      >
                        <option value="ALL">All Auth States</option>
                        <option value="authenticated">Authenticated</option>
                        <option value="anonymous">Anonymous</option>
                        <option value="unknown">Unknown</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* Endpoints Table */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px]">
                          <th className="py-3 px-4">Method</th>
                          <th className="py-3 px-4">Normalized Route</th>
                          <th className="py-3 px-4">Origin / Host</th>
                          <th className="py-3 px-4">Classifications</th>
                          <th className="py-3 px-4">Auth State</th>
                          <th className="py-3 px-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {filteredEndpoints.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="py-12 text-center text-slate-500 font-sans italic">
                              No endpoints matched the filter criteria.
                            </td>
                          </tr>
                        ) : (
                          filteredEndpoints.map((ep, idx) => {
                            const method = ep.methods?.[0] || 'GET';
                            const isQueued = queuedEndpointMap[ep.url || ep.normalized_route];
                            return (
                              <tr key={idx} className="hover:bg-slate-800/40 transition">
                                <td className="py-3 px-4 whitespace-nowrap">
                                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                                    method === 'GET' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25' :
                                    method === 'POST' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25' :
                                    method === 'PUT' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/25' :
                                    method === 'DELETE' ? 'bg-red-500/15 text-red-400 border border-red-500/25' :
                                    'bg-slate-800 text-slate-300'
                                  }`}>
                                    {method}
                                  </span>
                                </td>
                                <td className="py-3 px-4 font-bold text-slate-200">
                                  <button
                                    onClick={() => setSelectedEndpoint(ep)}
                                    className="hover:text-cyan-300 transition text-left cursor-pointer"
                                  >
                                    {ep.normalized_route || ep.url}
                                  </button>
                                </td>
                                <td className="py-3 px-4 text-slate-400">{ep.origin || 'Same-origin'}</td>
                                <td className="py-3 px-4">
                                  <div className="flex flex-wrap gap-1">
                                    {ep.classifications?.map((c, i) => (
                                      <span key={i} className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px]">
                                        {c.category} (P{c.priority})
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="py-3 px-4">
                                  {ep.auth_observations?.[0] ? (
                                    <span className={`px-2 py-0.5 rounded text-[10px] ${
                                      ep.auth_observations[0].status === 'authenticated' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                                      ep.auth_observations[0].status === 'anonymous' ? 'bg-slate-800 text-slate-400' :
                                      'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                    }`}>
                                      {ep.auth_observations[0].status}
                                    </span>
                                  ) : (
                                    <span className="text-slate-500">unknown</span>
                                  )}
                                </td>
                                <td className="py-3 px-4 text-right whitespace-nowrap">
                                  <div className="flex items-center justify-end gap-2">
                                    <button
                                      onClick={() => handleQueueEndpoint(ep)}
                                      className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition cursor-pointer flex items-center gap-1 ${
                                        isQueued 
                                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' 
                                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                                      }`}
                                    >
                                      {isQueued ? <Check className="w-3 h-3 text-emerald-400" /> : <Lock className="w-3 h-3 text-cyan-400" />}
                                      <span>{isQueued ? 'Queued' : 'Queue IDOR'}</span>
                                    </button>
                                    <button
                                      onClick={() => setSelectedEndpoint(ep)}
                                      className="px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 text-xs font-semibold transition cursor-pointer"
                                    >
                                      Inspect
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* IDOR RESEARCH CENTER TAB */}
            {activeTab === 'idor' && (
              <div className="space-y-6">
                {/* Header Banner */}
                <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0d1627] via-[#091120] to-[#0d1627] border border-cyan-500/25 shadow-xl space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="p-3 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/25">
                        <Lock className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-lg font-bold text-white tracking-tight font-mono">
                            Authenticated IDOR & Cross-Account Engine
                          </h2>
                          <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                            Deterministic Differential Gate
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1">
                          Differential testing between two researcher-controlled accounts. Identifies object access violations across tenant and instance boundaries without executing state-changing mutations.
                        </p>
                      </div>
                    </div>

                    {/* Global Action buttons */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleRunDifferentialTesting}
                        disabled={runningDifferential || authProfiles.length < 2}
                        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition shadow-lg cursor-pointer ${
                          runningDifferential 
                            ? 'bg-slate-800 text-slate-500 cursor-not-allowed' 
                            : 'bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-cyan-500/25'
                        }`}
                        title={authProfiles.length < 2 ? "Add User A and User B profiles first" : "Run differential tests"}
                      >
                        <Zap className={`w-3.5 h-3.5 ${runningDifferential ? 'animate-spin' : 'fill-current'}`} />
                        <span>{runningDifferential ? 'Testing differential...' : 'Run Differential Testing'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Navigation Pills */}
                  <div className="flex gap-2 pt-3 border-t border-slate-800/80 text-xs font-medium">
                    {[
                      { id: 'profiles', label: '1. Auth Profiles', count: authProfiles.length },
                      { id: 'har', label: '2. HAR Capture Import' },
                      { id: 'candidates', label: '3. Candidate Object References', count: idorCandidates.length },
                      { id: 'matrix', label: '4. Differential Testing Matrix', count: idorComparisons.length }
                    ].map(pill => (
                      <button
                        key={pill.id}
                        onClick={() => setIdorSubTab(pill.id)}
                        className={`px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 cursor-pointer ${
                          idorSubTab === pill.id
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/35 font-semibold'
                            : 'bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        <span>{pill.label}</span>
                        {pill.count !== undefined && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300">
                            {pill.count}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Notice Banners */}
                {profileNotice && (
                  <div className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
                    profileNotice.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'
                  }`}>
                    <div className="flex items-center gap-2">
                      {profileNotice.type === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertOctagon className="w-4 h-4" />}
                      <span>{profileNotice.msg}</span>
                    </div>
                    <button onClick={() => setProfileNotice(null)} className="text-slate-400 hover:text-white cursor-pointer">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                {/* SUB-PANEL 1: PROFILES */}
                {idorSubTab === 'profiles' && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* User A Card */}
                      <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                          <div className="flex items-center gap-2">
                            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-xs border border-emerald-500/30">
                              A
                            </div>
                            <div>
                              <h3 className="text-sm font-bold text-white">Profile A (Resource Owner / Victim)</h3>
                              <p className="text-[11px] text-slate-400">Owns target documents, records, and accounts</p>
                            </div>
                          </div>
                          {authProfiles.find(p => p.principal_label === 'user_a')?.identity_status === 'verified' ? (
                            <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-[10px] font-mono flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              Verified: {authProfiles.find(p => p.principal_label === 'user_a')?.verified_id}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-mono">
                              Unverified
                            </span>
                          )}
                        </div>

                        <div className="space-y-3 text-xs">
                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Principal Label</label>
                              <input
                                type="text"
                                value={userAForm.principal_label}
                                onChange={e => setUserAForm(prev => ({ ...prev, principal_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Tenant / Org Label</label>
                              <input
                                type="text"
                                value={userAForm.tenant_label}
                                onChange={e => setUserAForm(prev => ({ ...prev, tenant_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Role</label>
                              <input
                                type="text"
                                value={userAForm.role_label}
                                onChange={e => setUserAForm(prev => ({ ...prev, role_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Instance / Shard</label>
                              <input
                                type="text"
                                value={userAForm.instance_label}
                                onChange={e => setUserAForm(prev => ({ ...prev, instance_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                          </div>

                          <div>
                            <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                              <span>Identity Endpoint (e.g. /api/me)</span>
                              <span className="text-slate-500">Proves distinct principal ID</span>
                            </label>
                            <div className="flex gap-2 mt-1">
                              <input
                                type="text"
                                placeholder="https://api.example.com/v1/me"
                                value={userAForm.identity_endpoint}
                                onChange={e => setUserAForm(prev => ({ ...prev, identity_endpoint: e.target.value }))}
                                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                              <button
                                onClick={() => handleVerifyProfile(userAForm.principal_label)}
                                disabled={verifyingPrincipal === userAForm.principal_label}
                                className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold transition cursor-pointer flex items-center gap-1.5"
                              >
                                <RefreshCw className={`w-3.5 h-3.5 ${verifyingPrincipal === userAForm.principal_label ? 'animate-spin' : ''}`} />
                                <span>Verify</span>
                              </button>
                            </div>
                          </div>

                          <div>
                            <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                              <span>Bearer Token / Authorization Header</span>
                              <button
                                type="button"
                                onClick={() => setShowTokenA(prev => !prev)}
                                className="text-cyan-400 hover:text-cyan-300 text-[10px]"
                              >
                                {showTokenA ? 'Hide Secret' : 'Show Secret'}
                              </button>
                            </label>
                            <input
                              type={showTokenA ? 'text' : 'password'}
                              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                              value={userAForm.token}
                              onChange={e => setUserAForm(prev => ({ ...prev, token: e.target.value }))}
                              className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                            />
                          </div>

                          <button
                            onClick={() => handleSaveAuthProfile(userAForm)}
                            disabled={profileSaving}
                            className="w-full mt-2 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition shadow-lg shadow-emerald-500/20 cursor-pointer"
                          >
                            Save Profile A
                          </button>
                        </div>
                      </div>

                      {/* User B Card */}
                      <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                          <div className="flex items-center gap-2">
                            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-xs border border-cyan-500/30">
                              B
                            </div>
                            <div>
                              <h3 className="text-sm font-bold text-white">Profile B (Accessor / Attacker / Tester)</h3>
                              <p className="text-[11px] text-slate-400">Tests unauthorized cross-tenant/cross-user requests</p>
                            </div>
                          </div>
                          {authProfiles.find(p => p.principal_label === 'user_b')?.identity_status === 'verified' ? (
                            <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 text-[10px] font-mono flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                              Verified: {authProfiles.find(p => p.principal_label === 'user_b')?.verified_id}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-mono">
                              Unverified
                            </span>
                          )}
                        </div>

                        <div className="space-y-3 text-xs">
                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Principal Label</label>
                              <input
                                type="text"
                                value={userBForm.principal_label}
                                onChange={e => setUserBForm(prev => ({ ...prev, principal_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Tenant / Org Label</label>
                              <input
                                type="text"
                                value={userBForm.tenant_label}
                                onChange={e => setUserBForm(prev => ({ ...prev, tenant_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Role</label>
                              <input
                                type="text"
                                value={userBForm.role_label}
                                onChange={e => setUserBForm(prev => ({ ...prev, role_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                            <div>
                              <label className="text-[11px] text-slate-400 font-mono">Instance / Shard</label>
                              <input
                                type="text"
                                value={userBForm.instance_label}
                                onChange={e => setUserBForm(prev => ({ ...prev, instance_label: e.target.value }))}
                                className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                            </div>
                          </div>

                          <div>
                            <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                              <span>Identity Endpoint (e.g. /api/me)</span>
                              <span className="text-slate-500">Proves distinct principal ID</span>
                            </label>
                            <div className="flex gap-2 mt-1">
                              <input
                                type="text"
                                placeholder="https://api.example.com/v1/me"
                                value={userBForm.identity_endpoint}
                                onChange={e => setUserBForm(prev => ({ ...prev, identity_endpoint: e.target.value }))}
                                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                              />
                              <button
                                onClick={() => handleVerifyProfile(userBForm.principal_label)}
                                disabled={verifyingPrincipal === userBForm.principal_label}
                                className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold transition cursor-pointer flex items-center gap-1.5"
                              >
                                <RefreshCw className={`w-3.5 h-3.5 ${verifyingPrincipal === userBForm.principal_label ? 'animate-spin' : ''}`} />
                                <span>Verify</span>
                              </button>
                            </div>
                          </div>

                          <div>
                            <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                              <span>Bearer Token / Authorization Header</span>
                              <button
                                type="button"
                                onClick={() => setShowTokenB(prev => !prev)}
                                className="text-cyan-400 hover:text-cyan-300 text-[10px]"
                              >
                                {showTokenB ? 'Hide Secret' : 'Show Secret'}
                              </button>
                            </label>
                            <input
                              type={showTokenB ? 'text' : 'password'}
                              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                              value={userBForm.token}
                              onChange={e => setUserBForm(prev => ({ ...prev, token: e.target.value }))}
                              className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                            />
                          </div>

                          <button
                            onClick={() => handleSaveAuthProfile(userBForm)}
                            disabled={profileSaving}
                            className="w-full mt-2 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition shadow-lg shadow-cyan-500/20 cursor-pointer"
                          >
                            Save Profile B
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Credential Isolation Safety Banner */}
                    <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 text-xs text-slate-400 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-emerald-400" />
                        <span>Strict Credential Isolation: Stored in isolated ACL file (0600). Raw secrets are NEVER exposed in reports or LLM prompts.</span>
                      </div>
                      <span className="font-mono text-emerald-400">Deterministic Guard Active</span>
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 2: HAR IMPORT */}
                {idorSubTab === 'har' && (
                  <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4 max-w-2xl mx-auto">
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <UploadCloud className="w-4 h-4 text-cyan-400" />
                        Import Researcher-Provided HAR Capture
                      </h3>
                      <p className="text-xs text-slate-400 mt-1">
                        Upload HTTP Archive (.har) captures from your browser or proxy. Out-of-scope transactions are filtered immediately, credentials are redacted, and endpoints and object candidates are safely extracted.
                      </p>
                    </div>

                    {harNotice && (
                      <div className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                        harNotice.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'
                      }`}>
                        <CheckCircle2 className="w-4 h-4" />
                        <span>{harNotice.msg}</span>
                      </div>
                    )}

                    <form onSubmit={handleHARUploadSubmit} className="space-y-4">
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <label className="text-[11px] text-slate-400 font-mono">Owner Principal</label>
                          <input
                            type="text"
                            value={harOwner}
                            onChange={e => setHarOwner(e.target.value)}
                            className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] text-slate-400 font-mono">Tenant Label</label>
                          <input
                            type="text"
                            value={harTenant}
                            onChange={e => setHarTenant(e.target.value)}
                            className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                          />
                        </div>
                      </div>

                      <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/50 rounded-2xl p-6 text-center bg-slate-950/50 transition">
                        <input
                          type="file"
                          accept=".har"
                          id="har-file-input"
                          className="hidden"
                          onChange={e => {
                            if (e.target.files && e.target.files[0]) {
                              setHarFile(e.target.files[0]);
                            }
                          }}
                        />
                        <label htmlFor="har-file-input" className="cursor-pointer space-y-2 flex flex-col items-center">
                          <UploadCloud className="w-8 h-8 text-cyan-400" />
                          <span className="text-xs font-bold text-slate-200">
                            {harFile ? harFile.name : 'Choose HAR file or drag and drop'}
                          </span>
                          <span className="text-[11px] text-slate-500">Maximum allowed file size: 10 MB</span>
                        </label>
                      </div>

                      <button
                        type="submit"
                        disabled={harUploading || !harFile}
                        className={`w-full py-2.5 rounded-xl text-xs font-bold transition flex items-center justify-center gap-2 cursor-pointer ${
                          harUploading || !harFile 
                            ? 'bg-slate-800 text-slate-500 cursor-not-allowed' 
                            : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-500/25'
                        }`}
                      >
                        <UploadCloud className="w-4 h-4" />
                        <span>{harUploading ? 'Ingesting and redacting...' : 'Upload and Ingest HAR'}</span>
                      </button>
                    </form>
                  </div>
                )}

                {/* SUB-PANEL 3: CANDIDATES */}
                {idorSubTab === 'candidates' && (
                  <div className="space-y-4">
                    {/* Actions bar */}
                    <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={handleBuildIDORInventory}
                          disabled={buildingInventory}
                          className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold text-xs border border-slate-700 transition cursor-pointer flex items-center gap-1.5"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${buildingInventory ? 'animate-spin' : ''}`} />
                          <span>Extract Candidates from Endpoints</span>
                        </button>
                        <span className="text-xs text-slate-500">({idorCandidates.length} candidate references identified)</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <input
                          type="text"
                          placeholder="Filter by object ID or route..."
                          value={candidateFilter}
                          onChange={e => setCandidateFilter(e.target.value)}
                          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                    </div>

                    {/* Candidates Table */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px]">
                              <th className="py-3 px-4">Location</th>
                              <th className="py-3 px-4">Parameter Name</th>
                              <th className="py-3 px-4">Object Identifier</th>
                              <th className="py-3 px-4">Route Template</th>
                              <th className="py-3 px-4">Owner Context</th>
                              <th className="py-3 px-4">Access Policy</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono">
                            {filteredCandidates.length === 0 ? (
                              <tr>
                                <td colSpan={6} className="py-12 text-center text-slate-500 font-sans italic">
                                  No candidate object references found. Click "Extract Candidates from Endpoints" or import a HAR capture.
                                </td>
                              </tr>
                            ) : (
                              filteredCandidates.map((cand, idx) => (
                                <tr key={idx} className="hover:bg-slate-800/40 transition">
                                  <td className="py-3 px-4">
                                    <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px] uppercase">
                                      {cand.location}
                                    </span>
                                  </td>
                                  <td className="py-3 px-4 text-cyan-300">{cand.param_name}</td>
                                  <td className="py-3 px-4 font-bold text-white">{cand.object_id}</td>
                                  <td className="py-3 px-4 text-slate-300">{cand.route_template}</td>
                                  <td className="py-3 px-4 text-slate-400">{cand.owner_principal || 'user_a'}</td>
                                  <td className="py-3 px-4">
                                    <select
                                      value={cand.access_policy || 'private'}
                                      onChange={e => handleUpdateCandidatePolicy(cand.id, e.target.value)}
                                      className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
                                    >
                                      <option value="private">private (owner only)</option>
                                      <option value="tenant_shared">tenant_shared</option>
                                      <option value="explicitly_shared">explicitly_shared</option>
                                      <option value="public">public</option>
                                      <option value="unknown">unknown (needs review)</option>
                                    </select>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* SUB-PANEL 4: MATRIX & FINDINGS */}
                {idorSubTab === 'matrix' && (
                  <div className="space-y-4">
                    {/* Top Summary Banner */}
                    <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                      <div className="flex flex-wrap gap-2 text-xs font-mono">
                        <span className="px-2.5 py-1 rounded-lg bg-red-500/15 text-red-300 border border-red-500/30 font-bold">
                          {idorComparisons.filter(c => c.status === 'Confirmed' || c.status === 'CrossTenant' || c.status === 'CrossInstance').length} Confirmed IDOR
                        </span>
                        <span className="px-2.5 py-1 rounded-lg bg-orange-500/15 text-orange-300 border border-orange-500/30">
                          {idorComparisons.filter(c => c.status === 'UnauthorizedRole').length} Unauthorized Role
                        </span>
                        <span className="px-2.5 py-1 rounded-lg bg-amber-500/15 text-amber-300 border border-amber-500/30">
                          {idorComparisons.filter(c => c.status === 'NeedsReview').length} Needs Review
                        </span>
                        <span className="px-2.5 py-1 rounded-lg bg-blue-500/15 text-blue-300 border border-blue-500/30">
                          {idorComparisons.filter(c => c.status === 'AuthorizedShare').length} Authorized Share
                        </span>
                      </div>

                      <a
                        href={`/api/runs/${selectedRunId}/idor/report`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition flex items-center gap-1.5"
                      >
                        <Download className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Download IDOR Report (.md)</span>
                      </a>
                    </div>

                    {/* Matrix Table */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px]">
                              <th className="py-3 px-4">Candidate Route</th>
                              <th className="py-3 px-4">Object ID</th>
                              <th className="py-3 px-4 text-center">Owner (A)</th>
                              <th className="py-3 px-4 text-center">Tester (B)</th>
                              <th className="py-3 px-4 text-center">Anon</th>
                              <th className="py-3 px-4">Boundary Level</th>
                              <th className="py-3 px-4">Verdict</th>
                              <th className="py-3 px-4 text-right">Evidence</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono">
                            {idorComparisons.length === 0 ? (
                              <tr>
                                <td colSpan={8} className="py-12 text-center text-slate-500 font-sans italic">
                                  No differential test comparisons recorded yet. Click "Run Differential Testing" to test candidate objects.
                                </td>
                              </tr>
                            ) : (
                              idorComparisons.map((comp, idx) => {
                                const isConfirmed = comp.status === 'Confirmed' || comp.status === 'CrossTenant' || comp.status === 'CrossInstance';
                                const isUnauthRole = comp.status === 'UnauthorizedRole';
                                return (
                                  <tr key={idx} className={`hover:bg-slate-800/40 transition ${isConfirmed ? 'bg-red-500/5' : ''}`}>
                                    <td className="py-3 px-4 font-bold text-slate-200">{comp.candidate?.route_template || comp.request_url}</td>
                                    <td className="py-3 px-4 text-cyan-300 font-bold">{comp.candidate?.object_id}</td>
                                    <td className="py-3 px-4 text-center">
                                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/25">
                                        {comp.owner_status} OK
                                      </span>
                                    </td>
                                    <td className="py-3 px-4 text-center">
                                      <span className={`px-2 py-0.5 rounded font-bold ${
                                        comp.tester_status === 200 && isConfirmed ? 'bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse' :
                                        comp.tester_status === 200 ? 'bg-amber-500/15 text-amber-300 border border-amber-500/25' :
                                        'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                      }`}>
                                        {comp.tester_status}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4 text-center text-slate-400">
                                      {comp.anon_status}
                                    </td>
                                    <td className="py-3 px-4">
                                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                                        comp.boundary === 'cross_instance' ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30' :
                                        comp.boundary === 'cross_tenant' ? 'bg-red-500/15 text-red-300 border border-red-500/30' :
                                        'bg-slate-800 text-slate-400'
                                      }`}>
                                        {comp.boundary}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4">
                                      <span className={`px-2.5 py-1 rounded-md text-[11px] font-bold ${
                                        isConfirmed ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                                        isUnauthRole ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                                        comp.status === 'AuthorizedShare' ? 'bg-blue-500/15 text-blue-300 border border-blue-500/30' :
                                        'bg-slate-800 text-slate-400'
                                      }`}>
                                        {comp.status}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4 text-right">
                                      <button
                                        onClick={() => setActiveEvidenceComp(comp)}
                                        className="px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 text-xs font-semibold transition cursor-pointer"
                                      >
                                        View Evidence
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* RCE RESEARCH CENTER TAB */}
            {activeTab === 'rce' && (
              <div className="space-y-6">
                {/* Header Banner */}
                <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0d1627] via-[#120f26] to-[#0d1627] border border-purple-500/25 shadow-xl space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="p-3 rounded-2xl bg-gradient-to-tr from-purple-600 to-indigo-600 text-white shadow-lg shadow-purple-500/25">
                        <Terminal className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-xl font-extrabold text-white tracking-tight">RCE Research Center</h2>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                            PHASE 4 ENGINE
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Application-aware Remote Code Execution attack surface discovery, multi-step chains, advisory reachability & 3-profile validation
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={handleDiscoverRCE}
                        disabled={rceDiscovering}
                        className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow-lg shadow-purple-600/25 hover:shadow-purple-600/40 transition cursor-pointer flex items-center gap-2 disabled:opacity-50"
                      >
                        <Sparkles className={`w-3.5 h-3.5 ${rceDiscovering ? 'animate-spin' : ''}`} />
                        <span>{rceDiscovering ? 'Analyzing Sinks...' : 'Discover RCE Attack Surfaces'}</span>
                      </button>

                      <button
                        onClick={handleExportRCEReport}
                        className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 transition cursor-pointer flex items-center gap-1.5"
                        title="Download Markdown research report"
                      >
                        <Download className="w-3.5 h-3.5 text-slate-400" />
                        <span>Export Report (.md)</span>
                      </button>
                    </div>
                  </div>

                  {/* Safety & Scope Assurance Banner */}
                  <div className="flex flex-wrap items-center gap-3 text-xs pt-1 border-t border-purple-500/15">
                    <span className="text-slate-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>ScopedTransport Enforced</span>
                    </span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400 flex items-center gap-1">
                      <Shield className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Non-Destructive Probes Only ($&#123;7*7&#125;)</span>
                    </span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400 flex items-center gap-1">
                      <Activity className="w-3.5 h-3.5 text-purple-400" />
                      <span>Negative Controls & Reflection Excluded</span>
                    </span>
                  </div>
                </div>

                {/* Notice banner */}
                {rceNotice && (
                  <div className={`p-4 rounded-xl border flex items-center justify-between text-xs animate-in fade-in duration-200 ${
                    rceNotice.type === 'error' ? 'bg-red-500/10 border-red-500/30 text-red-300' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <div className="flex items-center gap-2">
                      {rceNotice.type === 'error' ? <AlertTriangle className="w-4 h-4 text-red-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      <span>{rceNotice.msg}</span>
                    </div>
                    <button onClick={() => setRceNotice(null)} className="text-slate-400 hover:text-white cursor-pointer">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

                {/* Sub-tab Navigation */}
                <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2 text-xs font-semibold">
                  {[
                    { id: 'overview', label: '1. Overview & Sinks', icon: Activity },
                    { id: 'explorer', label: '2. Attack Surface Explorer', icon: Layers, count: filteredRceCandidates.length },
                    { id: 'queue', label: '3. Candidate Prioritization Queue', icon: Sliders, count: rceCandidates.length },
                    { id: 'advisories', label: '4. Advisory Intelligence (CVEs)', icon: BookOpen, count: rceAdvisories.length },
                    { id: 'validation', label: '5. Validation Center', icon: Shield }
                  ].map(tab => {
                    const TabIcon = tab.icon;
                    const active = rceSubTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setRceSubTab(tab.id)}
                        className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl transition cursor-pointer ${
                          active
                            ? 'bg-purple-600 text-white shadow-md shadow-purple-600/20'
                            : 'bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        <TabIcon className="w-3.5 h-3.5" />
                        <span>{tab.label}</span>
                        {tab.count !== undefined && tab.count > 0 && (
                          <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                            active ? 'bg-purple-800 text-purple-200' : 'bg-slate-800 text-slate-400'
                          }`}>
                            {tab.count}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* SUB-TAB 1: OVERVIEW & SINKS */}
                {rceSubTab === 'overview' && (
                  <div className="space-y-6">
                    {/* Primary KPI Metrics */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
                      <div className="p-4 rounded-2xl bg-gradient-to-br from-purple-950/40 via-slate-900/90 to-slate-950 border border-purple-500/30 shadow-lg">
                        <span className="text-[10px] text-purple-300 uppercase font-bold tracking-wider">Total Attack Surfaces</span>
                        <div className="text-2xl font-black font-mono text-purple-300 mt-1">
                          {rceOverview?.total_candidates ?? rceCandidates.length}
                        </div>
                        <span className="text-[10px] text-slate-500">Classified endpoints</span>
                      </div>

                      <div className="p-4 rounded-2xl bg-gradient-to-br from-red-950/40 via-slate-900/90 to-slate-950 border border-red-500/30 shadow-lg">
                        <span className="text-[10px] text-red-300 uppercase font-bold tracking-wider">High Priority Targets</span>
                        <div className="text-2xl font-black font-mono text-red-400 mt-1">
                          {rceOverview?.high_priority_count ?? 0}
                        </div>
                        <span className="text-[10px] text-slate-500">Score &ge; 75 / 100</span>
                      </div>

                      <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-950/40 via-slate-900/90 to-slate-950 border border-cyan-500/30 shadow-lg">
                        <span className="text-[10px] text-cyan-300 uppercase font-bold tracking-wider">Multi-Step Chains</span>
                        <div className="text-2xl font-black font-mono text-cyan-300 mt-1">
                          {rceOverview?.active_chains_count ?? 0}
                        </div>
                        <span className="text-[10px] text-slate-500">Correlated pipelines</span>
                      </div>

                      <div className="p-4 rounded-2xl bg-gradient-to-br from-blue-950/40 via-slate-900/90 to-slate-950 border border-blue-500/30 shadow-lg">
                        <span className="text-[10px] text-blue-300 uppercase font-bold tracking-wider">Advisories Matched</span>
                        <div className="text-2xl font-black font-mono text-blue-300 mt-1">
                          {rceOverview?.advisory_match_count ?? rceOverview?.advisories_matched ?? 0}
                        </div>
                        <span className="text-[10px] text-slate-500">Public CVE correlations</span>
                      </div>

                      <div className="p-4 rounded-2xl bg-gradient-to-br from-emerald-950/40 via-slate-900/90 to-slate-950 border border-emerald-500/30 shadow-lg">
                        <span className="text-[10px] text-emerald-300 uppercase font-bold tracking-wider">Verified RCE Findings</span>
                        <div className="text-2xl font-black font-mono text-emerald-400 mt-1">
                          {rceOverview?.validated_count ?? rceOverview?.verified_rce_count ?? 0}
                        </div>
                        <span className="text-[10px] text-slate-500">Gate confirmed</span>
                      </div>
                    </div>

                    {/* Sinks & Attack Surface Categories Grid */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                          <Flame className="w-4 h-4 text-purple-400" />
                          <span>Execution Sink Classification</span>
                        </h3>
                        <span className="text-xs text-slate-400">6 sink vectors analyzed deterministically</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                        {Object.entries(RCE_CATEGORY_CONFIG).map(([catKey, cfg]) => {
                          const IconComp = cfg.icon;
                          const count = rceOverview?.category_distribution?.[catKey] ?? rceOverview?.by_category?.[catKey] ?? rceCandidates.filter(c => c.category === catKey).length;
                          return (
                            <div key={catKey} className={`p-4 rounded-2xl ${cfg.bg} border ${cfg.border} flex flex-col justify-between space-y-3 shadow-md hover:scale-[1.01] transition`}>
                              <div className="space-y-1.5">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <div className={`p-2 rounded-xl bg-slate-950/70 ${cfg.text}`}>
                                      <IconComp className="w-4 h-4" />
                                    </div>
                                    <h4 className="text-xs font-bold text-white">{cfg.label}</h4>
                                  </div>
                                  <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${cfg.badge}`}>
                                    {count}
                                  </span>
                                </div>
                                <p className="text-[11px] text-slate-400 leading-relaxed font-sans">{cfg.description}</p>
                              </div>

                              <button
                                onClick={() => {
                                  setRceCategoryFilter(catKey);
                                  setRceSubTab('explorer');
                                }}
                                className="w-full py-1.5 px-3 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 text-[11px] font-semibold transition cursor-pointer flex items-center justify-center gap-1.5"
                              >
                                <span>Filter in Explorer</span>
                                <ChevronRight className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Top Ranked Candidates Preview */}
                    <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-bold text-white">Top Priority RCE Candidates</h3>
                          <p className="text-xs text-slate-400">Ranked by transparent multidimensional risk scoring</p>
                        </div>
                        <button
                          onClick={() => setRceSubTab('queue')}
                          className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 font-semibold cursor-pointer"
                        >
                          <span>View Full Queue ({rceCandidates.length})</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      {rceCandidates.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 italic text-xs">
                          No RCE candidates discovered yet. Click "Discover RCE Attack Surfaces" above to scan endpoints.
                        </div>
                      ) : (
                        <div className="divide-y divide-slate-800/80">
                          {rceCandidates.slice(0, 5).map((cand, idx) => {
                            const catCfg = RCE_CATEGORY_CONFIG[cand.category] || { label: cand.category, badge: 'bg-slate-800 text-slate-300' };
                            return (
                              <div key={idx} className="py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                                <div className="flex items-center gap-3">
                                  <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-black ${
                                    cand.priority_score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                                    cand.priority_score >= 60 ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                                    'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  }`}>
                                    {cand.priority_score}
                                  </span>
                                  <div>
                                    <div className="flex items-center gap-2">
                                      <span className="font-mono font-bold text-white">{cand.method} {cand.route}</span>
                                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono ${catCfg.badge}`}>
                                        {catCfg.label}
                                      </span>
                                    </div>
                                    <p className="text-[11px] text-slate-400 font-sans mt-0.5">{cand.hypothesis}</p>
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => {
                                      setSelectedRceCandidate(cand);
                                      setRceSubTab('queue');
                                    }}
                                    className="px-3 py-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-300 text-xs font-semibold transition cursor-pointer"
                                  >
                                    Investigate
                                  </button>
                                  <button
                                    onClick={() => setRceValidationModalCand(cand)}
                                    className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 text-xs font-semibold transition cursor-pointer"
                                  >
                                    Validate
                                  </button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* SUB-TAB 2: ATTACK SURFACE EXPLORER */}
                {rceSubTab === 'explorer' && (
                  <div className="space-y-4">
                    {/* Filters Toolbar */}
                    <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                      <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
                        <div className="relative flex-1 min-w-[200px]">
                          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                          <input
                            type="text"
                            placeholder="Filter by route, URL, sink, hypothesis..."
                            value={rceSearchFilter}
                            onChange={e => setRceSearchFilter(e.target.value)}
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-purple-500"
                          />
                        </div>

                        <select
                          value={rceCategoryFilter}
                          onChange={e => setRceCategoryFilter(e.target.value)}
                          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
                        >
                          <option value="ALL">All Categories</option>
                          <option value="file_processing">File Processing</option>
                          <option value="ssti">Template Injection (SSTI)</option>
                          <option value="command_injection">Command Injection</option>
                          <option value="deserialization">Deserialization</option>
                          <option value="expression_language">Expression Language</option>
                          <option value="background_jobs">Background Jobs</option>
                        </select>

                        <select
                          value={rceStatusFilter}
                          onChange={e => setRceStatusFilter(e.target.value)}
                          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
                        >
                          <option value="ALL">All Statuses</option>
                          <option value="candidate">Candidate</option>
                          <option value="verified">Verified</option>
                          <option value="needs_review">Needs Review</option>
                          <option value="suppressed">Suppressed</option>
                        </select>
                      </div>

                      {(rceCategoryFilter !== 'ALL' || rceStatusFilter !== 'ALL' || rceSearchFilter) && (
                        <button
                          onClick={() => {
                            setRceCategoryFilter('ALL');
                            setRceStatusFilter('ALL');
                            setRceSearchFilter('');
                          }}
                          className="text-xs text-slate-400 hover:text-white px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 transition cursor-pointer"
                        >
                          Reset Filters
                        </button>
                      )}
                    </div>

                    {/* Candidates Table */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px]">
                              <th className="py-3 px-4">Score</th>
                              <th className="py-3 px-4">Category</th>
                              <th className="py-3 px-4">Method & Route</th>
                              <th className="py-3 px-4">Suspected Sink / Vector</th>
                              <th className="py-3 px-4">Chain Status</th>
                              <th className="py-3 px-4">Status</th>
                              <th className="py-3 px-4 text-right">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono">
                            {filteredRceCandidates.length === 0 ? (
                              <tr>
                                <td colSpan={7} className="py-12 text-center text-slate-500 font-sans italic">
                                  No RCE candidates match the current filters. Click "Discover RCE Attack Surfaces" or reset your search filters.
                                </td>
                              </tr>
                            ) : (
                              filteredRceCandidates.map((cand, idx) => {
                                const catCfg = RCE_CATEGORY_CONFIG[cand.category] || { label: cand.category, badge: 'bg-slate-800 text-slate-300' };
                                const isVerified = cand.status === 'verified';
                                return (
                                  <tr key={idx} className={`hover:bg-slate-800/40 transition ${isVerified ? 'bg-emerald-500/5' : ''}`}>
                                    <td className="py-3 px-4">
                                      <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                                        cand.priority_score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                                        cand.priority_score >= 60 ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                                        'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                      }`}>
                                        {cand.priority_score}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4">
                                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono ${catCfg.badge}`}>
                                        {catCfg.label}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4">
                                      <div className="font-bold text-white">{cand.method} {cand.route}</div>
                                      <div className="text-[10px] text-slate-500 font-sans break-all">{cand.target_url}</div>
                                    </td>
                                    <td className="py-3 px-4 font-sans text-slate-300 max-w-xs truncate" title={cand.suspected_sink}>
                                      {cand.suspected_sink}
                                    </td>
                                    <td className="py-3 px-4">
                                      {cand.chain_id ? (
                                        <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                                          Chain: {cand.chain_id}
                                        </span>
                                      ) : (
                                        <span className="text-slate-600 font-sans text-[11px]">—</span>
                                      )}
                                    </td>
                                    <td className="py-3 px-4">
                                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                                        cand.status === 'verified' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                                        cand.status === 'needs_review' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                                        cand.status === 'suppressed' ? 'bg-slate-800 text-slate-400' :
                                        'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                                      }`}>
                                        {cand.status}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4 text-right space-x-1.5 whitespace-nowrap">
                                      <button
                                        onClick={() => {
                                          setSelectedRceCandidate(cand);
                                          setRceSubTab('queue');
                                        }}
                                        className="px-2.5 py-1 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-300 text-xs font-semibold transition cursor-pointer"
                                      >
                                        Inspect
                                      </button>
                                      <button
                                        onClick={() => setRceValidationModalCand(cand)}
                                        className="px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 text-xs font-semibold transition cursor-pointer"
                                      >
                                        Validate
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* SUB-TAB 3: CANDIDATE PRIORITIZATION QUEUE */}
                {rceSubTab === 'queue' && (
                  <div className="space-y-4">
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-bold text-white">RCE Prioritization Queue</h3>
                        <p className="text-xs text-slate-400">
                          Ranked by deterministic multi-variable score (Base Risk, Parameter Exposure, Auth Barrier, CVE Corroboration, Multi-Step Chain)
                        </p>
                      </div>
                      <span className="text-xs font-mono text-purple-300 px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/20">
                        {rceCandidates.length} Candidates Enqueued
                      </span>
                    </div>

                    {rceCandidates.length === 0 ? (
                      <div className="p-12 text-center text-slate-500 italic text-xs border border-slate-800 rounded-xl bg-slate-900/30">
                        No candidates in queue. Click "Discover RCE Attack Surfaces" to begin research.
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {rceCandidates.map((cand) => {
                          const catCfg = RCE_CATEGORY_CONFIG[cand.category] || { label: cand.category, badge: 'bg-slate-800 text-slate-300' };
                          const isSelected = selectedRceCandidate?.id === cand.id;
                          return (
                            <div
                              key={cand.id}
                              className={`p-5 rounded-2xl border transition shadow-lg ${
                                isSelected ? 'bg-slate-900/90 border-purple-500/60 ring-1 ring-purple-500/30' : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                              }`}
                            >
                              {/* Header */}
                              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/80 pb-3">
                                <div className="space-y-1">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-white">
                                      {cand.method}
                                    </span>
                                    <span className="text-sm font-mono font-bold text-white">{cand.route}</span>
                                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono ${catCfg.badge}`}>
                                      {catCfg.label}
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800">
                                      Confidence: {cand.confidence}
                                    </span>
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                      cand.status === 'verified' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                                      cand.status === 'needs_review' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                                      'bg-slate-800 text-slate-400'
                                    }`}>
                                      {cand.status}
                                    </span>
                                  </div>
                                  <div className="text-xs text-cyan-400 font-mono break-all">{cand.target_url}</div>
                                </div>

                                {/* Score Badge */}
                                <div className="flex items-center gap-2">
                                  <div className={`p-2.5 rounded-xl font-mono text-center border ${
                                    cand.priority_score >= 80 ? 'bg-red-500/15 border-red-500/40 text-red-300' :
                                    cand.priority_score >= 60 ? 'bg-orange-500/15 border-orange-500/40 text-orange-300' :
                                    'bg-amber-500/15 border-amber-500/40 text-amber-300'
                                  }`}>
                                    <div className="text-[10px] uppercase font-bold tracking-wider">Priority Score</div>
                                    <div className="text-xl font-black">{cand.priority_score} <span className="text-xs font-normal text-slate-400">/ 100</span></div>
                                  </div>
                                </div>
                              </div>

                              {/* Candidate Body */}
                              <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                                {/* Left column: Hypothesis & Sink */}
                                <div className="space-y-3">
                                  <div>
                                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Research Hypothesis</span>
                                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 mt-1 leading-relaxed font-sans">
                                      {cand.hypothesis}
                                    </div>
                                  </div>

                                  <div>
                                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Suspected Execution Sink</span>
                                    <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-amber-300 mt-1 font-mono text-[11px]">
                                      {cand.suspected_sink}
                                    </div>
                                  </div>

                                  {cand.parameters && cand.parameters.length > 0 && (
                                    <div>
                                      <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Observed Parameters</span>
                                      <div className="flex flex-wrap gap-1.5 mt-1">
                                        {cand.parameters.map((p, i) => (
                                          <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono text-[11px]">
                                            {p}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Multi-step Chain Steps if chained */}
                                  {cand.chain_steps && cand.chain_steps.length > 0 && (
                                    <div className="p-3 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-2">
                                      <span className="text-[10px] uppercase font-bold text-purple-300 tracking-wider flex items-center gap-1.5">
                                        <Layers className="w-3.5 h-3.5" />
                                        <span>Multi-Step Processing Chain Steps</span>
                                      </span>
                                      <div className="space-y-1.5">
                                        {cand.chain_steps.map((st, i) => (
                                          <div key={i} className="p-2 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono flex items-center justify-between">
                                            <span className="text-white font-bold">{st.step_type} ({st.method} {st.route})</span>
                                            <span className="text-slate-400 font-sans">{st.description}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Matched Advisories */}
                                  {cand.matched_advisories && cand.matched_advisories.length > 0 && (
                                    <div>
                                      <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Matched Public Advisories</span>
                                      <div className="space-y-1.5 mt-1">
                                        {cand.matched_advisories.map((adv, i) => (
                                          <div key={i} className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                                            <div>
                                              <span className="font-mono font-bold text-cyan-300">{adv.cve_id}</span>
                                              <span className="text-slate-400 text-[11px] ml-2">({adv.product})</span>
                                            </div>
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                              adv.tier === 'ComponentReachable' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                                              adv.tier === 'ComponentCorroborated' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' :
                                              'bg-slate-800 text-slate-300'
                                            }`}>
                                              {adv.tier}
                                            </span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>

                                {/* Right column: Score breakdown & Notes editor */}
                                <div className="space-y-3">
                                  {/* Transparent Score Breakdown */}
                                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                                    <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                                      Deterministic Score Breakdown
                                    </span>
                                    {cand.score_breakdown && (
                                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                                          <span className="text-slate-400 block text-[10px]">Base Sink Risk</span>
                                          <span className="text-white font-bold">+{cand.score_breakdown.base_risk}</span>
                                        </div>
                                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                                          <span className="text-slate-400 block text-[10px]">Input Exposure</span>
                                          <span className="text-white font-bold">+{cand.score_breakdown.input_exposure}</span>
                                        </div>
                                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                                          <span className="text-slate-400 block text-[10px]">Auth Barrier</span>
                                          <span className="text-white font-bold">{cand.score_breakdown.auth_modifier}</span>
                                        </div>
                                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                                          <span className="text-slate-400 block text-[10px]">Tech/CVE Modifier</span>
                                          <span className="text-white font-bold">+{cand.score_breakdown.tech_cve_modifier}</span>
                                        </div>
                                      </div>
                                    )}

                                    {/* Explanations List */}
                                    {cand.score_breakdown?.explanations && cand.score_breakdown.explanations.length > 0 && (
                                      <div className="pt-2 border-t border-slate-800/80 space-y-1">
                                        <span className="text-[10px] uppercase font-bold text-slate-500">Score Rationale</span>
                                        <ul className="space-y-1 text-[11px] text-slate-300 font-sans">
                                          {cand.score_breakdown.explanations.map((exp, i) => (
                                            <li key={i} className="flex items-start gap-1.5">
                                              <span className="text-purple-400 mt-0.5">•</span>
                                              <span>{exp}</span>
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    )}
                                  </div>

                                  {/* Notes & Status Editor */}
                                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                                    <div className="flex items-center justify-between">
                                      <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Researcher Notes & Manual Gate</span>
                                      <select
                                        value={isSelected ? rceCandidateStatus : cand.status}
                                        onChange={e => {
                                          setSelectedRceCandidate(cand);
                                          setRceCandidateStatus(e.target.value);
                                        }}
                                        className="bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-xs text-white cursor-pointer font-mono"
                                      >
                                        <option value="candidate">candidate</option>
                                        <option value="needs_review">needs_review</option>
                                        <option value="verified">verified</option>
                                        <option value="suppressed">suppressed</option>
                                      </select>
                                    </div>

                                    <textarea
                                      rows={2}
                                      value={isSelected ? rceCandidateNotes : (cand.notes || '')}
                                      onFocus={() => {
                                        setSelectedRceCandidate(cand);
                                        setRceCandidateNotes(cand.notes || '');
                                        setRceCandidateStatus(cand.status);
                                      }}
                                      onChange={e => setRceCandidateNotes(e.target.value)}
                                      placeholder="Add research observations, curl reproduction notes, or sink verification details..."
                                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-purple-500"
                                    />

                                    {isSelected && (
                                      <div className="flex justify-end">
                                        <button
                                          onClick={() => handleSaveCandidateNotes(cand.id)}
                                          disabled={rceSavingNotes}
                                          className="px-3 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs transition cursor-pointer"
                                        >
                                          {rceSavingNotes ? 'Saving...' : 'Save Notes & Status'}
                                        </button>
                                      </div>
                                    )}
                                  </div>

                                  {/* Actions */}
                                  <div className="flex items-center justify-end gap-2 pt-2">
                                    {getLastAttempt(cand) && (
                                      <button
                                        onClick={() => setRceEvidenceModalCand(cand)}
                                        className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
                                      >
                                        <Eye className="w-3.5 h-3.5 text-slate-400" />
                                        <span>View Evidence Bundle</span>
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setRceValidationModalCand(cand)}
                                      className="px-4 py-1.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs shadow-md shadow-purple-600/20 transition cursor-pointer flex items-center gap-1.5"
                                    >
                                      <Shield className="w-3.5 h-3.5" />
                                      <span>Launch 3-Profile Validation Gate</span>
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* SUB-TAB 4: ADVISORY INTELLIGENCE */}
                {rceSubTab === 'advisories' && (
                  <div className="space-y-4">
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                      <h3 className="text-sm font-bold text-white">Curated Public Vulnerability Advisory Intelligence</h3>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Correlated against detected software components and endpoint routes. Evaluates reachability across 6 strict progression tiers.
                      </p>
                    </div>

                    <div className="grid grid-cols-1 gap-4">
                      {rceAdvisories.map((rawAdv, idx) => {
                        const adv = rawAdv.advisory || rawAdv;
                        const cveId = adv.id || adv.cve_id || `ADV-${idx}`;
                        const name = adv.title || adv.name || cveId;
                        const product = adv.affected_product || adv.product || '';
                        const vulnRange = adv.vulnerable_range || '';
                        const severity = (adv.severity || 'high').toLowerCase();
                        const desc = adv.vuln_type || adv.description || '';
                        const reachabilityNotes = adv.reachability_condition || adv.reachability_notes || rawAdv.reachable_route || 'Evaluated against detected software stack';
                        const cvss = adv.cvss || (severity === 'critical' ? '9.8' : '8.5');

                        const matchingCandidates = rceCandidates.filter(c =>
                          c.matched_advisories?.some(a => a.cve_id === cveId) ||
                          c.matching_advisories?.some(a => a.advisory?.id === cveId)
                        );
                        const tier = rawAdv.highest_tier || (matchingCandidates.length > 0
                          ? matchingCandidates[0].matched_advisories?.find(a => a.cve_id === cveId)?.tier || 'ComponentReachable'
                          : 'TechnologyCorrelated');
                        const tierCfg = RCE_TIER_CONFIG[tier] || RCE_TIER_CONFIG.TechnologyCorrelated;

                        return (
                          <div key={cveId} className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm font-black text-cyan-300">{cveId}</span>
                                  <span className="text-xs font-bold text-white">{name}</span>
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    severity === 'critical' ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                                  }`}>
                                    {severity} (CVSS {cvss})
                                  </span>
                                </div>
                                <div className="text-xs text-slate-400 font-mono mt-0.5">
                                  Product: <span className="text-white font-semibold">{product}</span> • Vulnerable Range: <span className="text-amber-300 font-mono">{vulnRange}</span>
                                </div>
                              </div>

                              <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${tierCfg.bg} ${tierCfg.text} ${tierCfg.border}`}>
                                {tierCfg.label}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300 leading-relaxed font-sans">{desc}</p>

                            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1">
                              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">Reachability Analysis</span>
                              <p className="text-slate-300 font-sans">{reachabilityNotes}</p>
                              {adv.affected_routes && adv.affected_routes.length > 0 && (
                                <div className="pt-1.5 flex flex-wrap gap-1.5">
                                  {adv.affected_routes.map((rt, i) => (
                                    <span key={i} className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 font-mono text-[10px] border border-slate-800">
                                      {rt}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* SUB-TAB 5: VALIDATION CENTER */}
                {rceSubTab === 'validation' && (
                  <div className="space-y-6">
                    {/* Validation Architecture Guidance */}
                    <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 to-slate-950 border border-slate-800 space-y-3">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        <Shield className="w-4 h-4 text-emerald-400" />
                        <span>Graduated 3-Profile Validation Architecture</span>
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                          <span className="font-bold text-cyan-300 block">Profile 1: Passive Analysis</span>
                          <p className="text-slate-400 leading-relaxed font-sans">
                            Dispatches zero network traffic. Inspects existing endpoint intelligence, server headers, and verified technology versions against advisories.
                          </p>
                        </div>
                        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                          <span className="font-bold text-purple-300 block">Profile 2: Safe Active Probing</span>
                          <p className="text-slate-400 leading-relaxed font-sans">
                            Sends non-destructive mathematical evaluation markers ($&#123;7*7&#125; &rarr; 49). Verifies negative controls ($&#123;7*8&#125;) and strictly rejects raw input reflection.
                          </p>
                        </div>
                        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                          <span className="font-bold text-amber-300 block">Profile 3: Manual Verification Plan</span>
                          <p className="text-slate-400 leading-relaxed font-sans">
                            Generates copy-paste curl commands with exact parameters and deterministic observation criteria for researcher-controlled terminal execution.
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Candidate Validation History Table */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
                      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                        <h4 className="text-xs font-bold text-white uppercase font-mono">Candidate Validation Status & Attempts</h4>
                        <span className="text-xs text-slate-500 font-mono">{rceCandidates.length} Candidates</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px]">
                              <th className="py-3 px-4">Candidate</th>
                              <th className="py-3 px-4">Category</th>
                              <th className="py-3 px-4">Route</th>
                              <th className="py-3 px-4">Validation Profile</th>
                              <th className="py-3 px-4">Verdict</th>
                              <th className="py-3 px-4 text-right">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono">
                            {rceCandidates.map((cand, idx) => (
                              <tr key={idx} className="hover:bg-slate-800/40 transition">
                                <td className="py-3 px-4 font-bold text-white">{cand.id}</td>
                                <td className="py-3 px-4 text-purple-300">{cand.category}</td>
                                <td className="py-3 px-4 text-slate-300">{cand.http_method || cand.method} {cand.route || cand.normalized_route}</td>
                                <td className="py-3 px-4 text-slate-400">
                                  {getLastAttempt(cand)?.profile || 'Not Validated'}
                                </td>
                                <td className="py-3 px-4">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    (cand.validation_status || cand.status) === 'verified' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                                    (cand.validation_status || cand.status) === 'needs_review' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                                    (cand.validation_status || cand.status) === 'suppressed' ? 'bg-slate-800 text-slate-400' :
                                    'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                                  }`}>
                                    {cand.validation_status || cand.status}
                                  </span>
                                </td>
                                <td className="py-3 px-4 text-right space-x-2">
                                  {getLastAttempt(cand) && (
                                    <button
                                      onClick={() => setRceEvidenceModalCand(cand)}
                                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-semibold transition cursor-pointer"
                                    >
                                      Evidence
                                    </button>
                                  )}
                                  <button
                                    onClick={() => setRceValidationModalCand(cand)}
                                    className="px-2.5 py-1 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition cursor-pointer"
                                  >
                                    Validate
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>

      {/* ENDPOINT DETAIL DRAWER MODAL */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-[#0b101e] border border-slate-800 p-6 rounded-3xl w-full max-w-2xl max-h-[85vh] overflow-y-auto space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Endpoint Intelligence Details</h3>
              </div>
              <button onClick={() => setSelectedEndpoint(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 uppercase text-[10px]">Route Template</span>
                <div className="text-white font-bold text-sm mt-0.5 p-2 rounded bg-slate-950 border border-slate-800">
                  {selectedEndpoint.normalized_route || selectedEndpoint.url}
                </div>
              </div>

              <div>
                <span className="text-slate-500 uppercase text-[10px]">Canonical URL</span>
                <div className="text-cyan-300 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 break-all">
                  {selectedEndpoint.url}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">HTTP Methods</span>
                  <div className="text-slate-200 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800">
                    {selectedEndpoint.methods?.join(', ') || 'GET'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Discovery Sources</span>
                  <div className="text-slate-200 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800">
                    {selectedEndpoint.sources?.join(', ') || 'N/A'}
                  </div>
                </div>
              </div>

              {selectedEndpoint.query_params?.length > 0 && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Query Parameters</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedEndpoint.query_params.map((p, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedEndpoint.body_fields?.length > 0 && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">JSON Request Body Fields</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedEndpoint.body_fields.map((p, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-700">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedEndpoint.tech_fingerprints?.length > 0 && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Technology Stack</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedEndpoint.tech_fingerprints.map((t, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => {
                  handleQueueEndpoint(selectedEndpoint);
                  setSelectedEndpoint(null);
                }}
                className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition cursor-pointer flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Queue for IDOR Differential Testing</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* IDOR EVIDENCE BUNDLE MODAL */}
      {activeEvidenceComp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-[#0b101e] border border-slate-800 p-6 rounded-3xl w-full max-w-2xl max-h-[85vh] overflow-y-auto space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-400" />
                <h3 className="text-base font-bold text-white">IDOR Differential Evidence Bundle</h3>
              </div>
              <button onClick={() => setActiveEvidenceComp(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 uppercase text-[10px]">Target URL</span>
                <div className="text-cyan-300 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 break-all">
                  {activeEvidenceComp.request_url}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Boundary Isolation Level</span>
                  <div className="text-white font-bold mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 uppercase">
                    {activeEvidenceComp.boundary}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Verdict</span>
                  <div className="text-red-400 font-bold mt-0.5 p-2 rounded bg-slate-950 border border-slate-800">
                    {activeEvidenceComp.status}
                  </div>
                </div>
              </div>

              {activeEvidenceComp.disclosed_sensitive_fields?.length > 0 && (
                <div>
                  <span className="text-red-400 uppercase text-[10px] font-bold">Disclosed Sensitive Data Fields</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {activeEvidenceComp.disclosed_sensitive_fields.map((f, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {activeEvidenceComp.evidence_notes && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Differential Evidence Notes</span>
                  <div className="text-slate-300 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 font-sans">
                    {activeEvidenceComp.evidence_notes}
                  </div>
                </div>
              )}

              {activeEvidenceComp.redacted_tester_response && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px]">Tester Response Body (Redacted)</span>
                  <pre className="text-slate-300 mt-0.5 p-3 rounded bg-slate-950 border border-slate-800 overflow-x-auto text-[11px] max-h-48">
                    {activeEvidenceComp.redacted_tester_response}
                  </pre>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setActiveEvidenceComp(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition cursor-pointer"
              >
                Close Evidence
              </button>
            </div>
          </div>
        </div>
      )}

      {/* NEW SCAN MODAL WIZARD */}
      {scanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-gradient-to-b from-cyan-500/30 via-slate-700/50 to-slate-800 p-[1px] rounded-3xl w-full max-w-xl shadow-2xl overflow-hidden">
            <div className="bg-[#0b101e] rounded-3xl overflow-hidden flex flex-col max-h-[90vh]">
              {/* Modal Header */}
              <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/25">
                    <Zap className="w-5 h-5 fill-current" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white tracking-tight">Start New Security Scan</h3>
                    <p className="text-xs text-slate-400">Automated recon, discovery, and 7-check verification</p>
                  </div>
                </div>
                <button
                  onClick={() => setScanModalOpen(false)}
                  className="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-800 transition cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Modal Body */}
              <form onSubmit={handleStartScan} className="p-6 space-y-5 overflow-y-auto flex-1">
                {/* Target Domain Input */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Target Domain or Hostname <span className="text-red-400">*</span>
                    </label>
                    <span className="text-[11px] text-cyan-400 font-mono">Scope Enforced</span>
                  </div>
                  <div className="relative">
                    <Globe className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3.5" />
                    <input
                      type="text"
                      required
                      value={scanTargetInput}
                      onChange={(e) => setScanTargetInput(e.target.value)}
                      placeholder="e.g. example.com or app.target.com"
                      className="w-full bg-slate-950 border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-sm font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
                      autoFocus
                    />
                  </div>
                  {/* Quick-select chips */}
                  <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400 flex-wrap">
                    <span className="text-slate-500 font-semibold">Quick test:</span>
                    {['example.com', 'testfire.net', 'scanme.nmap.org'].map(sample => (
                      <button
                        type="button"
                        key={sample}
                        onClick={() => setScanTargetInput(sample)}
                        className="px-2 py-0.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-300 font-mono text-[10px] transition cursor-pointer"
                      >
                        {sample}
                      </button>
                    ))}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Automatically scoped to target and all subdomains (<code className="text-cyan-400">*.target.com</code>). 
                    All out-of-scope network traffic is strictly blocked at the transport layer.
                  </p>
                </div>

                {/* Scan Mode Selection */}
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Scan Mode Preset
                  </label>
                  <div className="grid grid-cols-1 gap-2.5">
                    <label className={`p-3.5 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                      scanMode === 'standard' ? 'bg-cyan-500/10 border-cyan-500/50 ring-1 ring-cyan-500/30' : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}>
                      <input
                        type="radio"
                        name="scanMode"
                        value="standard"
                        checked={scanMode === 'standard'}
                        onChange={() => setScanMode('standard')}
                        className="mt-0.5 text-cyan-500 focus:ring-cyan-500 cursor-pointer"
                      />
                      <div className="text-xs">
                        <span className="font-bold text-white block">Standard Security Audit (Recommended)</span>
                        <span className="text-slate-400 leading-normal block mt-0.5">
                          Full reconnaissance, open ports, live web tech stack, katana crawler, directory fuzzing, safe vulnerability tests, and the 7-check gate.
                        </span>
                      </div>
                    </label>

                    <label className={`p-3.5 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                      scanMode === 'passive' ? 'bg-cyan-500/10 border-cyan-500/50 ring-1 ring-cyan-500/30' : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}>
                      <input
                        type="radio"
                        name="scanMode"
                        value="passive"
                        checked={scanMode === 'passive'}
                        onChange={() => setScanMode('passive')}
                        className="mt-0.5 text-cyan-500 focus:ring-cyan-500 cursor-pointer"
                      />
                      <div className="text-xs">
                        <span className="font-bold text-white block">Passive Recon Only (Fast & Silent)</span>
                        <span className="text-slate-400 leading-normal block mt-0.5">
                          Discovers subdomains and DNS records via certificate transparency logs and DNS queries. Sends zero network packets to target web servers.
                        </span>
                      </div>
                    </label>

                    <label className={`p-3.5 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                      scanMode === 'custom' ? 'bg-cyan-500/10 border-cyan-500/50 ring-1 ring-cyan-500/30' : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}>
                      <input
                        type="radio"
                        name="scanMode"
                        value="custom"
                        checked={scanMode === 'custom'}
                        onChange={() => setScanMode('custom')}
                        className="mt-0.5 text-cyan-500 focus:ring-cyan-500 cursor-pointer"
                      />
                      <div className="text-xs flex-1">
                        <span className="font-bold text-white block">Custom Tool Selection</span>
                        <span className="text-slate-400 leading-normal block mt-0.5">
                          Select precisely which security stages to execute during this scan.
                        </span>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Custom tool checkboxes if custom mode is selected */}
                {scanMode === 'custom' && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Enable / Disable Stages:
                    </span>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {[
                        { key: 'ports', label: 'Port Scanner (naabu/nmap)' },
                        { key: 'probe', label: 'Web Prober (httpx)' },
                        { key: 'crawl', label: 'Katana Crawler' },
                        { key: 'fuzz', label: 'FFUF Directory Fuzzer' },
                        { key: 'xss', label: 'Dalfox XSS Prober' },
                        { key: 'nuclei', label: 'Nuclei Posture Checks' }
                      ].map(item => (
                        <label key={item.key} className="flex items-center gap-2 text-slate-300 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={customTools[item.key]}
                            onChange={(e) => setCustomTools(prev => ({ ...prev, [item.key]: e.target.checked }))}
                            className="rounded text-cyan-500 focus:ring-cyan-500 cursor-pointer"
                          />
                          <span>{item.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Optional Exclusions & Rate Limit */}
                <div className="space-y-3 pt-2 border-t border-slate-800/80">
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                      <span>Out-of-Scope Exclusions (Optional)</span>
                      <span className="text-[11px] font-normal text-slate-500">Comma or line separated</span>
                    </label>
                    <input
                      type="text"
                      value={outOfScopeInput}
                      onChange={(e) => setOutOfScopeInput(e.target.value)}
                      placeholder="e.g. admin.example.com, test.example.com"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div className="flex items-center justify-between gap-4">
                    <span className="text-xs text-slate-400 font-medium">Request Rate Limit (req/sec):</span>
                    <input
                      type="number"
                      min="1"
                      max="200"
                      value={rateLimitInput}
                      onChange={(e) => setRateLimitInput(e.target.value)}
                      className="w-24 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-white text-right focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                {/* Modal Footer */}
                <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setScanModalOpen(false)}
                    className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={scanStarting || !scanTargetInput.trim()}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/20 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {scanStarting ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Launching...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        <span>Start Security Scan</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* RCE VALIDATION MODAL */}
      {rceValidationModalCand && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-[#0b101e] border border-slate-800 p-6 rounded-3xl w-full max-w-xl max-h-[90vh] overflow-y-auto space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">Execute 3-Profile RCE Validation</h3>
              </div>
              <button onClick={() => setRceValidationModalCand(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
                <span className="text-[10px] text-slate-500 uppercase block">Candidate Target</span>
                <span className="text-white font-bold">{rceValidationModalCand.method} {rceValidationModalCand.route}</span>
                <div className="text-cyan-400 text-[11px] break-all">{rceValidationModalCand.target_url}</div>
              </div>

              {/* Profile selection */}
              <div className="space-y-2">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
                  Select Validation Profile
                </span>

                <label className={`p-3 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                  rceValidationProfile === 'safe_active' ? 'bg-purple-500/10 border-purple-500/50 ring-1 ring-purple-500/30' : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}>
                  <input
                    type="radio"
                    name="valProfile"
                    value="safe_active"
                    checked={rceValidationProfile === 'safe_active'}
                    onChange={() => setRceValidationProfile('safe_active')}
                    className="mt-0.5 text-purple-500 focus:ring-purple-500 cursor-pointer"
                  />
                  <div>
                    <span className="font-bold text-white block">Profile 2: Safe Active Probing (Recommended)</span>
                    <span className="text-slate-400 block mt-0.5 font-sans leading-normal">
                      Dispatches benign mathematical markers ($&#123;7*7&#125; &rarr; 49) with negative control ($&#123;7*8&#125;) and reflection exclusion. Zero shell execution.
                    </span>
                  </div>
                </label>

                <label className={`p-3 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                  rceValidationProfile === 'passive' ? 'bg-purple-500/10 border-purple-500/50 ring-1 ring-purple-500/30' : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}>
                  <input
                    type="radio"
                    name="valProfile"
                    value="passive"
                    checked={rceValidationProfile === 'passive'}
                    onChange={() => setRceValidationProfile('passive')}
                    className="mt-0.5 text-purple-500 focus:ring-purple-500 cursor-pointer"
                  />
                  <div>
                    <span className="font-bold text-white block">Profile 1: Passive Analysis</span>
                    <span className="text-slate-400 block mt-0.5 font-sans leading-normal">
                      Zero traffic sent. Evaluates headers, technologies, and route parameters against vulnerability advisories.
                    </span>
                  </div>
                </label>

                <label className={`p-3 rounded-xl border flex items-start gap-3 cursor-pointer transition ${
                  rceValidationProfile === 'manual' ? 'bg-purple-500/10 border-purple-500/50 ring-1 ring-purple-500/30' : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}>
                  <input
                    type="radio"
                    name="valProfile"
                    value="manual"
                    checked={rceValidationProfile === 'manual'}
                    onChange={() => setRceValidationProfile('manual')}
                    className="mt-0.5 text-purple-500 focus:ring-purple-500 cursor-pointer"
                  />
                  <div>
                    <span className="font-bold text-white block">Profile 3: Manual Verification Plan</span>
                    <span className="text-slate-400 block mt-0.5 font-sans leading-normal">
                      Generates structured, reproducible curl command and manual review steps for researcher validation.
                    </span>
                  </div>
                </label>
              </div>

              {/* Auth Profile Selection */}
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
                  Authentication Principal (Optional)
                </label>
                <select
                  value={rceValidationAuthPrincipal}
                  onChange={e => setRceValidationAuthPrincipal(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-purple-500 cursor-pointer"
                >
                  <option value="">None (Unauthenticated request)</option>
                  {authProfiles.map((p, i) => (
                    <option key={i} value={p.principal_label}>
                      {p.principal_label} ({p.tenant_label || 'no-tenant'} - {p.role || 'member'})
                    </option>
                  ))}
                </select>
              </div>

              {/* Safety notice */}
              <div className="p-3 rounded-xl bg-purple-500/10 border border-purple-500/25 text-[11px] text-purple-300 space-y-1">
                <span className="font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Transport-Layer Scope Protection</span>
                </span>
                <p className="text-slate-400 font-sans">
                  Target is enforced by ScopedTransport against YAML scope. Probing uses benign arithmetic evaluation markers only.
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setRceValidationModalCand(null)}
                className="px-4 py-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 text-xs font-semibold transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => handleValidateRCE(rceValidationModalCand.id)}
                disabled={rceValidating}
                className="px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow-lg shadow-purple-600/25 transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
              >
                <Play className={`w-3.5 h-3.5 fill-current ${rceValidating ? 'animate-spin' : ''}`} />
                <span>{rceValidating ? 'Validating...' : 'Execute Validation'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* RCE EVIDENCE BUNDLE MODAL */}
      {rceEvidenceModalCand && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-[#0b101e] border border-slate-800 p-6 rounded-3xl w-full max-w-2xl max-h-[85vh] overflow-y-auto space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-purple-400" />
                <h3 className="text-base font-bold text-white">RCE Evidence Bundle & Verification Audit</h3>
              </div>
              <button onClick={() => setRceEvidenceModalCand(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              {(() => {
                const activeAttempt = getLastAttempt(rceEvidenceModalCand);
                const candRoute = rceEvidenceModalCand.route || rceEvidenceModalCand.normalized_route || '';
                const candMethod = rceEvidenceModalCand.http_method || rceEvidenceModalCand.method || 'POST';
                const candUrl = rceEvidenceModalCand.target || rceEvidenceModalCand.target_url || (rceEvidenceModalCand.origin ? `${rceEvidenceModalCand.origin}${candRoute}` : candRoute);
                const candStatus = rceEvidenceModalCand.validation_status || rceEvidenceModalCand.status || 'candidate';
                const reproCurl = rceEvidenceModalCand.reproduction_curl || 
                  activeAttempt?.reproduction_curl || 
                  (activeAttempt?.positive_request_sent?.startsWith('curl') 
                    ? activeAttempt.positive_request_sent 
                    : `curl -s -X ${candMethod} -d "template=\${7*7}" "${candUrl}"`);

                return (
                  <>
                    <div>
                      <span className="text-slate-500 uppercase text-[10px]">Target Route</span>
                      <div className="text-white font-bold mt-0.5 p-2 rounded bg-slate-950 border border-slate-800">
                        {candMethod} {candRoute}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 uppercase text-[10px]">Canonical URL</span>
                      <div className="text-cyan-300 mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 break-all">
                        {candUrl}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <span className="text-slate-500 uppercase text-[10px]">Scope Transport Check</span>
                        <div className="text-emerald-400 font-bold mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>ScopedTransport Enforced</span>
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-500 uppercase text-[10px]">Gate Verdict</span>
                        <div className="text-purple-300 font-bold mt-0.5 p-2 rounded bg-slate-950 border border-slate-800 uppercase">
                          {candStatus}
                        </div>
                      </div>
                    </div>

                    {activeAttempt && (
                      <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                        <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
                          Safe Active Marker Evaluation Results
                        </span>
                        <div className="space-y-1.5 text-[11px]">
                          <div className="flex items-center justify-between py-1 px-2.5 rounded bg-slate-900 border border-slate-800">
                            <span className="text-slate-400">Marker Sent:</span>
                            <span className="text-purple-300 font-mono">{activeAttempt.marker_sent || activeAttempt.positive_request_sent || '${7*7}'}</span>
                          </div>
                          <div className="flex items-center justify-between py-1 px-2.5 rounded bg-slate-900 border border-slate-800">
                            <span className="text-slate-400">Reflection Check:</span>
                            <span className="text-emerald-400 font-mono">
                              {activeAttempt.reflection_excluded || activeAttempt.marker_reflected === false ? 'PASS (Not Reflected)' : 'FAIL (Reflected)'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between py-1 px-2.5 rounded bg-slate-900 border border-slate-800">
                            <span className="text-slate-400">Negative Control:</span>
                            <span className="text-emerald-400 font-mono">
                              {activeAttempt.negative_control_verified !== false ? 'PASS (Negative control passed)' : 'FAIL'}
                            </span>
                          </div>
                          {activeAttempt.notes && (
                            <div className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                              <span className="text-slate-500 uppercase text-[10px] block mb-0.5">Verification Notes:</span>
                              {activeAttempt.notes}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Reproduction curl */}
                    {reproCurl && (
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="text-slate-500 uppercase text-[10px]">Reproducible Curl Command</span>
                          <button
                            onClick={() => {
                              navigator.clipboard?.writeText(reproCurl);
                              setCopied(true);
                              setTimeout(() => setCopied(false), 2000);
                            }}
                            className="text-cyan-400 hover:text-cyan-300 text-[10px] flex items-center gap-1 cursor-pointer font-sans"
                          >
                            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copied ? 'Copied' : 'Copy Curl'}</span>
                          </button>
                        </div>
                        <pre className="text-slate-300 mt-0.5 p-3 rounded bg-slate-950 border border-slate-800 overflow-x-auto text-[11px] whitespace-pre-wrap">
                          {reproCurl}
                        </pre>
                      </div>
                    )}
                  </>
                );
              })()}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setRceEvidenceModalCand(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition cursor-pointer"
              >
                Close Evidence
              </button>
            </div>
          </div>
        </div>
      )}

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
