import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, Archive, ArrowUpRight, Ban, Bell, Check, ChevronDown, CircleDot, Cloud, Database, FileCode2, Fingerprint, Gauge, LayoutDashboard, LockKeyhole, Plus, RefreshCw, RotateCcw, Search, Shield, ShieldAlert, ShieldCheck, Terminal, Volume2, VolumeX, Zap } from 'lucide-react'

const API = import.meta.env.VITE_API_BASE || `http://${window.location.hostname}:8000`
type Token = { id: string; name: string; kind: string; environment: string; status: string; severity: string; created_at: string; triggered_at?: string | null; trigger_count: number; rotation_of?: string | null }
type Incident = { id: string; token_id: string; title: string; severity: string; status: string; latency_ms: number; rationale: string; created_at: string }
type SecurityEvent = { id: string; event_type: string; created_at: string }
type Summary = { active_honeytokens: number; triggered_decoys: number; open_incidents: number; total_events: number; median_latency_ms: number | null; mode: string }
type AuditEvent = { id: string; action: string; target_id: string | null; details: string; created_at: string }
type IpBlockEntry = { ip_address: string; failed_attempts: number; blocked: boolean; updated_at: string; blocked_at: string | null }
type IncidentStatus = 'all' | 'open' | 'acknowledged' | 'resolved'
type Severity = 'all' | 'low' | 'medium' | 'high' | 'critical'
type TimeRange = '24h' | '7d' | '30d' | 'all'
const timeRanges: Record<TimeRange, number | null> = { '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000, '30d': 30 * 24 * 60 * 60 * 1000, all: null }
const nav = [
  { label: 'Overview', icon: LayoutDashboard }, { label: 'Live Threats', icon: ShieldAlert },
  { label: 'Honeytokens', icon: Fingerprint }, { label: 'Deployment', icon: Cloud },
  { label: 'Incident Center', icon: AlertTriangle }, { label: 'Threat Analytics', icon: Gauge },
  { label: 'IP Protection', icon: Ban }, { label: 'Integrations', icon: Database }, { label: 'Audit Trail', icon: Archive },
]
const kindIcon: Record<string, typeof FileCode2> = { 'API credential': LockKeyhole, 'Config file': FileCode2, 'Cloud object': Cloud, 'Database record': Database, 'Sensitive document': Archive }
function timeAgo(value?: string | null) {
  if (!value) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}
function formatLocalTime(value: string) {
  const timestamp = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`
  return new Date(timestamp).toLocaleString()
}
function playAlertTone(context: AudioContext) {
  const oscillator = context.createOscillator()
  const gain = context.createGain()
  oscillator.frequency.value = 880
  gain.gain.setValueAtTime(0.12, context.currentTime)
  gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.18)
  oscillator.connect(gain)
  gain.connect(context.destination)
  oscillator.start()
  oscillator.stop(context.currentTime + 0.18)
}
async function api<T>(path: string, options?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API}${path}`, {
      ...options,
      headers: { ...(options?.body ? { 'Content-Type': 'application/json' } : {}), ...(options?.headers || {}) }
    })
  } catch {
    throw new Error(`Unable to reach the API at ${API}`)
  }
  if (!res.ok) {
    const body: { detail?: unknown } = await res.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (${res.status})`)
  }
  return res.json()
}
function exportIncidents(items: Incident[]) {
  const columns: Array<keyof Incident> = ['id', 'title', 'severity', 'status', 'token_id', 'latency_ms', 'created_at', 'rationale']
  const escapeCell = (value: string | number) => {
    const text = String(value).replace(/^[=+\-@]/, "'$&")
    return `"${text.replace(/"/g, '""')}"`
  }
  const csv = [
    columns.map(escapeCell).join(','),
    ...items.map(item => columns.map(column => escapeCell(item[column])).join(','))
  ].join('\r\n')
  const url = URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `canarywatch-incidents-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
function App() {
  const [page, setPage] = useState('Overview')
  const [tokens, setTokens] = useState<Token[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [connected, setConnected] = useState(false)
  const [unreadAlertIds, setUnreadAlertIds] = useState<string[]>([])
  const [soundEnabled, setSoundEnabled] = useState(false)
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')
  const soundEnabledRef = useRef(false)
  const audioContextRef = useRef<AudioContext | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [toast, setToast] = useState('')
  const [query, setQuery] = useState('')
  const [incidentQuery, setIncidentQuery] = useState('')
  const [incidentStatus, setIncidentStatus] = useState<IncidentStatus>('all')
  const [incidentSeverity, setIncidentSeverity] = useState<Severity>('all')
  const [showCreate, setShowCreate] = useState(false)
  const [showResetConfirm, setShowResetConfirm] = useState(false)
  const [name, setName] = useState('Repository config decoy')
  const [kind, setKind] = useState('API credential')
  const [severity, setSeverity] = useState('high')
  const [secret, setSecret] = useState('')
  soundEnabledRef.current = soundEnabled
  const rangeStart = timeRanges[timeRange] === null ? null : Date.now() - timeRanges[timeRange]!
  const rangeEvents = useMemo(() => events.filter(event => rangeStart === null || new Date(event.created_at).getTime() >= rangeStart), [events, rangeStart])
  const rangeIncidents = useMemo(() => incidents.filter(incident => rangeStart === null || new Date(incident.created_at).getTime() >= rangeStart), [incidents, rangeStart])
  const rangeLatencies = useMemo(() => rangeIncidents.map(incident => incident.latency_ms).sort((a, b) => a - b), [rangeIncidents])
  const rangeMedianLatency = rangeLatencies.length
    ? rangeLatencies.length % 2
      ? rangeLatencies[Math.floor(rangeLatencies.length / 2)]
      : (rangeLatencies[rangeLatencies.length / 2 - 1] + rangeLatencies[rangeLatencies.length / 2]) / 2
    : null
  const refresh = useCallback(async () => {
    try {
      const [t, i, e, s] = await Promise.all([
        api<Token[]>('/api/v1/honeytokens'),
        api<Incident[]>('/api/v1/incidents'),
        api<SecurityEvent[]>('/api/v1/events'),
        api<Summary>('/api/v1/dashboard/summary')
      ])
      setTokens(t); setIncidents(i); setEvents(e); setSummary(s); setError('')
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to connect to API') }
  }, [])
  useEffect(() => {
    let cancelled = false
    const initialize = async () => {
      try {
        await api('/api/v1/demo/start', { method: 'POST', body: '{}' })
        if (!cancelled) await refresh()
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Unable to initialize the demo')
      }
    }
    void initialize()
    return () => { cancelled = true }
  }, [refresh])
  useEffect(() => {
    let ws: WebSocket | undefined
    let timer: number | undefined
    let retryTimer: number | undefined
    let retryDelay = 1000
    let disposed = false
    const connect = () => {
      if (disposed) return
      try {
        ws = new WebSocket(API.replace(/^http/, 'ws') + '/api/v1/ws/alerts')
        ws.onopen = () => { setConnected(true); retryDelay = 1000 }
        ws.onclose = () => {
          setConnected(false)
          if (!disposed) {
            retryTimer = window.setTimeout(connect, retryDelay)
            retryDelay = Math.min(retryDelay * 2, 10000)
          }
        }
        ws.onerror = () => ws?.close()
        ws.onmessage = message => {
          void refresh()
          try {
            const alert = JSON.parse(message.data) as { incident?: { id?: string } }
            const incidentId = alert.incident?.id
            if (incidentId) {
              setUnreadAlertIds(previous => previous.includes(incidentId) ? previous : [...previous, incidentId])
              if (soundEnabledRef.current && audioContextRef.current?.state === 'running') playAlertTone(audioContextRef.current)
            }
            setToast('Live security event received')
          } catch {
            setError('Received an unreadable live alert from the API')
          }
        }
      } catch {
        setConnected(false)
        retryTimer = window.setTimeout(connect, retryDelay)
        retryDelay = Math.min(retryDelay * 2, 10000)
      }
    }
    connect()
    timer = window.setInterval(() => { if (ws?.readyState === WebSocket.OPEN) ws.send('ping') }, 25000)
    const poll = window.setInterval(refresh, 10000)
    return () => {
      disposed = true
      ws?.close()
      if (timer) window.clearInterval(timer)
      if (retryTimer) window.clearTimeout(retryTimer)
      window.clearInterval(poll)
    }
  }, [refresh])
  const action = async (fn: () => Promise<unknown>, message: string) => {
    setBusy(true); setError('')
    try { await fn(); await refresh(); setToast(message); window.setTimeout(() => setToast(''), 4000) }
    catch (e) { setError(e instanceof Error ? e.message : 'Action failed') }
    finally { setBusy(false) }
  }
  const createToken = async () => {
    await action(async () => {
      const created = await api<Token & { demo_secret_once?: string }>('/api/v1/honeytokens', {
        method: 'POST', body: JSON.stringify({ name, kind, environment: 'Local demo', severity })
      })
      setSecret(created.demo_secret_once || '')
      setShowCreate(false)
    }, 'Honeytoken created')
  }
  const filtered = useMemo(() => tokens.filter(t => `${t.name} ${t.kind} ${t.environment} ${t.status}`.toLowerCase().includes(query.toLowerCase())), [tokens, query])
  const filteredIncidents = useMemo(() => incidents.filter(incident => {
    const matchesText = `${incident.title} ${incident.id} ${incident.token_id} ${incident.rationale}`.toLowerCase().includes(incidentQuery.trim().toLowerCase())
    return matchesText
      && (incidentStatus === 'all' || incident.status === incidentStatus)
      && (incidentSeverity === 'all' || incident.severity === incidentSeverity)
  }), [incidents, incidentQuery, incidentSeverity, incidentStatus])
  const activePage = page === 'Overview' ? 'Overview' : page
  const trigger = (t: Token) => action(() => api(`/api/v1/demo/trigger/${t.id}`, { method: 'POST', body: '{}' }), `Triggered ${t.name}`)
  const rotate = (t: Token) => action(async () => {
    const replacement = await api<Token & { demo_secret_once?: string }>(`/api/v1/honeytokens/${t.id}/rotate`, { method: 'POST', body: '{}' })
    setSecret(replacement.demo_secret_once || '')
  }, `Rotated ${t.name}`)
  const revoke = (t: Token) => action(() => api(`/api/v1/honeytokens/${t.id}/revoke`, { method: 'POST', body: '{}' }), `Revoked ${t.name}`)
  const reset = () => action(async () => {
    await api('/api/v1/demo/reset', { method: 'POST', body: '{}' })
    setShowResetConfirm(false)
    setSecret('')
    setIncidentQuery('')
    setIncidentSeverity('all')
    setIncidentStatus('all')
  }, 'Demo reset')
  const toggleAlertSound = () => {
    if (soundEnabled) {
      setSoundEnabled(false)
      return
    }
    try {
      const context = audioContextRef.current || new AudioContext()
      audioContextRef.current = context
      setSoundEnabled(true)
      void context.resume().catch(e => {
        setSoundEnabled(false)
        setError(e instanceof Error ? `Unable to enable alert sound: ${e.message}` : 'Unable to enable alert sound')
      })
    } catch (e) {
      setError(e instanceof Error ? `Unable to enable alert sound: ${e.message}` : 'Unable to enable alert sound')
    }
  }
  const markAlertsRead = () => {
    setUnreadAlertIds([])
    setPage('Incident Center')
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={21}/><span/></div><div><strong>canary<span>watch</span></strong><small>DECEPTION SECURITY</small></div></div>
      <div className="workspace-label">WORKSPACE</div>
      <div className="environment"><span className="env-dot"/><div><b>Local environment</b><small>Controlled demo</small></div><ChevronDown size={15}/></div>
      <nav>{nav.map(item => { const Icon = item.icon; return <button key={item.label} className={`nav-item ${activePage === item.label ? 'selected' : ''}`} onClick={() => setPage(item.label)}><Icon size={17}/><span>{item.label}</span>{item.label === 'Live Threats' && summary?.open_incidents ? <i>{summary.open_incidents}</i> : null}</button> })}</nav>
      <div className="sidebar-bottom"><div className="mini-status"><span className="pulse-dot"/><div><b>Detection engine</b><small>{connected ? 'WebSocket connected' : 'Polling fallback'}</small></div></div><div className="profile"><div className="avatar">CW</div><div><b>Security Operator</b><small>Local demo account</small></div><ChevronDown size={15}/></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb">Workspace <span>/</span> <b>{page}</b></div><div className="top-actions"><div className={`live-pill ${connected ? 'online' : ''}`}><span/>{connected ? 'LIVE CONNECTION' : 'POLLING MODE'}</div><button className="icon-button notification-button" aria-label={`Notifications, ${unreadAlertIds.length} unread alerts, ${summary?.open_incidents || 0} open incidents`} title="View incidents and mark alerts read" onClick={markAlertsRead}><Bell size={18}/>{unreadAlertIds.length > 0 && <i className="unread-count">{unreadAlertIds.length > 99 ? '99+' : unreadAlertIds.length}</i>}</button>{unreadAlertIds.length > 0 && <button className="icon-button" aria-label="Mark all alerts read" title="Mark all alerts read" onClick={() => setUnreadAlertIds([])}><Check size={17}/></button>}<button className="icon-button" aria-label={soundEnabled ? 'Disable alert sound' : 'Enable alert sound'} title={soundEnabled ? 'Disable alert sound' : 'Enable alert sound'} onClick={() => void toggleAlertSound()}>{soundEnabled ? <Volume2 size={17}/> : <VolumeX size={17}/>}</button><div className="top-avatar">CW</div></div></header>
      <div className="content">
        <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-dot"/> AUTONOMOUS DECEPTION FRAMEWORK</div><h1>{page === 'Overview' ? 'Security overview' : page}</h1><p>{page === 'Overview' ? 'Catch the breach where it begins. No noisy log pipelines required.' : `Monitor and manage your CanaryWatch ${page.toLowerCase()} workspace.`}</p></div><div className="heading-actions">{(page === 'Overview' || page === 'Threat Analytics') && <label className="range-control">Time range<select aria-label="Dashboard time range" className="button secondary" value={timeRange} onChange={event => setTimeRange(event.target.value as TimeRange)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="all">All time</option></select></label>}<button className="button secondary" onClick={refresh}><RefreshCw size={15}/> Refresh</button><button className="button primary" onClick={() => setShowCreate(true)}><Plus size={16}/> Create honeytoken</button></div></div>
        {error && <div className="error-banner"><AlertTriangle size={16}/><span>{error}</span><button aria-label="Dismiss error" onClick={() => setError('')}>×</button></div>}
        {toast && <div className="toast"><Check size={16}/>{toast}<button onClick={() => setToast('')}>×</button></div>}
        {secret && <div className="secret-banner"><div><b>Demo token created — shown once</b><p>{secret}</p><small>This synthetic demo value is not a real service credential.</small></div><button className="button secondary" onClick={async () => { if (!navigator.clipboard) { setToast('Clipboard unavailable — copy the visible value manually'); return } try { await navigator.clipboard.writeText(secret); setToast('Demo secret copied'); setSecret('') } catch { setToast('Copy failed — the demo value is still visible') } }}>Copy & dismiss</button></div>}
        {(page === 'Overview' || page === 'Threat Analytics') && <>
          <div className="metric-grid">
            <Metric icon={<Fingerprint/>} label="Active honeytokens" value={summary?.active_honeytokens ?? '—'} foot="Current deployed assets" tone="green"/>
            <Metric icon={<ShieldAlert/>} label="Triggered decoys" value={rangeEvents.length} foot="In selected time range" tone="amber"/>
            <Metric icon={<AlertTriangle/>} label="Open incidents" value={rangeIncidents.filter(incident => incident.status === 'open').length} foot="Created in selected range" tone="red"/>
            <Metric icon={<Zap/>} label="Median processing" value={rangeMedianLatency == null ? '—' : `${rangeMedianLatency.toFixed(2)} ms`} foot="Selected range · backend time" tone="blue"/>
          </div>
          <div className="dashboard-grid">
            <section className="panel threat-panel"><PanelTitle title="Live incident stream" sub="Latest events from your deception layer" action="VIEW ALL" onAction={() => setPage('Live Threats')}/>{rangeIncidents.length === 0 ? <Empty icon={<ShieldCheck/>} title="No incidents in this range" text="Choose a wider time range or trigger a synthetic honeytoken."/> : rangeIncidents.slice(0, 5).map(i => <div className="incident-row" key={i.id}><div className={`severity-mark ${i.severity}`}/><div className="incident-info"><b>{i.title}</b><small>{i.id} · {timeAgo(i.created_at)}</small></div><div className="incident-right"><span className={`tag ${i.severity}`}>{i.severity}</span><small>{i.latency_ms.toFixed(2)} ms</small></div></div>)}</section>
            <section className="panel demo-panel"><div className="panel-kicker"><span className="kicker-icon"><Terminal size={17}/></span><span>INTERACTIVE DEMO</span><span className="demo-badge">SAFE SIMULATION</span></div><h2>Trigger the trap.</h2><p>Simulate unauthorized access to a synthetic honeytoken and watch CanaryWatch respond in real time.</p><div className="demo-flow"><div><Fingerprint/><small>CANARY</small></div><span/><div><Zap/><small>DETECT</small></div><span/><div><ShieldAlert/><small>ALERT</small></div></div><button className="button primary full" disabled={busy || !tokens.some(t => t.status === 'active')} onClick={() => { const t = tokens.find(x => x.status === 'active'); if (t) trigger(t) }}><Zap size={16}/>{busy ? 'Processing…' : 'Simulate unauthorized access'}</button><button className="reset-link" disabled={busy} onClick={() => setShowResetConfirm(true)}><RotateCcw size={13}/> Reset synthetic demo</button></section>
          </div>
          <section className="panel guided-scenario">
            <div className="guided-scenario-copy"><span className="eyebrow"><span className="eyebrow-dot"/> JUDGE-READY WALKTHROUGH</span><h2>Run a complete demo scenario</h2><p>Creates and triggers four fresh synthetic canaries, then opens the incident queue. Safe to repeat; reset restores the baseline.</p></div>
            <button className="button primary" disabled={busy} onClick={() => action(async () => { await api('/api/v1/demo/scenario', { method: 'POST' }); setPage('Incident Center') }, 'Four-canary scenario complete')}><Zap size={16}/>{busy ? 'Running scenario…' : 'Run 4-event scenario'}</button>
          </section>
        </>}
        {(page === 'Overview' || page === 'Honeytokens') && <section className="panel table-panel"><PanelTitle title="Honeytoken inventory" sub="Manage synthetic deception artifacts" action="VIEW ALL" onAction={() => setPage('Honeytokens')}/><div className="table-toolbar"><div className="search-field"><Search size={15}/><input placeholder="Search honeytokens…" value={query} onChange={e => setQuery(e.target.value)}/></div><span>{filtered.length} artifacts</span></div><div className="table-scroll"><table><thead><tr><th>ARTIFACT</th><th>TYPE</th><th>ENVIRONMENT</th><th>STATUS</th><th>SEVERITY</th><th>TRIGGERS</th><th>ACTIONS</th></tr></thead><tbody>{filtered.map(t => { const Icon = kindIcon[t.kind] || FileCode2; return <tr key={t.id}><td><div className="artifact-cell"><span className="artifact-icon"><Icon size={16}/></span><div><b>{t.name}</b><small>{t.id}</small></div></div></td><td>{t.kind}</td><td><span className="resource-dot"/>{t.environment}</td><td><span className={`status ${t.status}`}><span/>{t.status}</span></td><td><span className={`tag ${t.severity}`}>{t.severity}</span></td><td>{t.trigger_count}</td><td><div className="row-actions"><button title="Simulate trigger" aria-label={`Simulate trigger for ${t.name}`} disabled={t.status !== 'active' || busy} onClick={() => trigger(t)}><Zap size={15}/></button><button title="Rotate token" aria-label={`Rotate ${t.name}`} disabled={busy} onClick={() => rotate(t)}><RefreshCw size={15}/></button><button title="Revoke token" aria-label={`Revoke ${t.name}`} disabled={t.status === 'revoked' || busy} onClick={() => revoke(t)}><Ban size={15}/></button></div></td></tr> })}</tbody></table>{filtered.length === 0 && <Empty icon={<Fingerprint/>} title="No honeytokens found" text="Create a honeytoken or change your search."/ >}</div></section>}
        {(page === 'Live Threats' || page === 'Incident Center') && <section className="panel table-panel">
          <PanelTitle title="Incident queue" sub="Investigate events raised by triggered deception assets" action="REFRESH" onAction={refresh}/>
          <div className="table-toolbar">
            <div className="search-field"><Search size={15}/><input aria-label="Search incidents" placeholder="Search title, ID, or token…" value={incidentQuery} onChange={event => setIncidentQuery(event.target.value)}/></div>
            <label>Severity <select aria-label="Filter by severity" className="button secondary" value={incidentSeverity} onChange={event => setIncidentSeverity(event.target.value as Severity)}>{(['all', 'critical', 'high', 'medium', 'low'] as Severity[]).map(value => <option key={value} value={value}>{value === 'all' ? 'All severities' : value}</option>)}</select></label>
            <label>Status <select aria-label="Filter by status" className="button secondary" value={incidentStatus} onChange={event => setIncidentStatus(event.target.value as IncidentStatus)}>{(['all', 'open', 'acknowledged', 'resolved'] as IncidentStatus[]).map(value => <option key={value} value={value}>{value === 'all' ? 'All statuses' : value}</option>)}</select></label>
            <span>{filteredIncidents.length} / {incidents.length} incidents</span>
            <button className="button secondary" disabled={!filteredIncidents.length} onClick={() => { exportIncidents(filteredIncidents); setToast('Filtered incident CSV exported') }}>Export CSV</button>
          </div>
          {incidents.length === 0 ? <Empty icon={<ShieldCheck/>} title="All quiet" text="No incidents. Trigger a synthetic honeytoken to populate this queue."/> : filteredIncidents.length === 0 ? <Empty icon={<Search/>} title="No matching incidents" text="Try changing your search or filters."/> : filteredIncidents.map(i => <div className="incident-detail-row" key={i.id}><div className={`severity-mark ${i.severity}`}/><div className="incident-info"><b>{i.title}</b><small>{i.id} · token {i.token_id} · {new Date(i.created_at).toLocaleString()}</small><p>{i.rationale}</p></div><div className="incident-right"><span className={`tag ${i.severity}`}>{i.severity}</span><span className={`status ${i.status}`}>{i.status}</span><small>{i.latency_ms.toFixed(2)} ms measured</small><div className="row-actions"><button title="Acknowledge" disabled={i.status !== 'open' || busy} onClick={() => action(() => api(`/api/v1/incidents/${i.id}/acknowledge`, { method: 'POST', body: '{}' }), 'Incident acknowledged')}><Check size={15}/></button><button title="Resolve" disabled={i.status === 'resolved' || busy} onClick={() => action(() => api(`/api/v1/incidents/${i.id}/resolve`, { method: 'POST', body: '{}' }), 'Incident resolved')}><ShieldCheck size={15}/></button></div></div></div>)}
        </section>}
        {page === 'Deployment' && <section className="panel integration-grid"><PanelTitle title="Placement adapters" sub="Local demo adapters are simulated; external systems are not connected."/><Integration icon={<FileCode2/>} title="Repository canary files" status="Simulated" text="Demonstrates repository artifact lifecycle without writing to an external repository."/><Integration icon={<Cloud/>} title="Cloud storage" status="Interface only" text="Adapter boundary is prepared; configure and test a real provider before claiming deployment."/><Integration icon={<Database/>} title="Database records" status="Simulated" text="Synthetic database canary records in the local demo environment."/><Integration icon={<Archive/>} title="Endpoint files" status="Simulated" text="Local placement concept only; no endpoint agent is installed." /></section>}
        {page === 'Integrations' && <section className="panel integration-grid"><PanelTitle title="Integrations" sub="Provider connection status is reported honestly."/><Integration icon={<Cloud/>} title="Cloud provider adapters" status="Not connected" text="No cloud credentials or external changes are required for the demo."/><Integration icon={<FileCode2/>} title="GitHub / repositories" status="Not connected" text="Use a dedicated test repository and least-privilege permissions for a future integration."/><Integration icon={<Database/>} title="Database adapter" status="Local demo" text="Current demo uses SQLite for portability." /></section>}
        {page === 'Threat Analytics' && <section className="panel table-panel">
          <PanelTitle title="Latency analytics" sub="Measured local backend event-processing samples"/>
          <div className="analytics-stat-grid">
            <Metric icon={<Activity/>} label="Samples" value={rangeLatencies.length} foot="Selected time range" tone="blue"/>
            <Metric icon={<Zap/>} label="Minimum" value={rangeLatencies.length ? `${rangeLatencies[0].toFixed(2)} ms` : '—'} foot="Backend processing" tone="green"/>
            <Metric icon={<Gauge/>} label="95th percentile" value={rangeLatencies.length ? `${rangeLatencies[Math.min(Math.ceil(rangeLatencies.length * 0.95) - 1, rangeLatencies.length - 1)].toFixed(2)} ms` : '—'} foot="Backend processing" tone="amber"/>
            <Metric icon={<Activity/>} label="Maximum" value={rangeLatencies.length ? `${rangeLatencies[rangeLatencies.length - 1].toFixed(2)} ms` : '—'} foot="Backend processing" tone="red"/>
          </div>
          <p className="analytics-note">Statistics show measured backend processing time for events in the selected range; they exclude browser-to-server network time and do not represent real-world attack detection.</p>
          <div className="analytics-bars">{rangeIncidents.slice(0, 12).map((i, idx) => <div key={i.id} title={`${i.latency_ms.toFixed(2)} ms`}><span style={{height: `${Math.max(8, Math.min(100, i.latency_ms / Math.max(1, ...rangeIncidents.map(x => x.latency_ms)) * 100))}%`}}/><small>{idx + 1}</small></div>)}</div>
          {rangeIncidents.length === 0 && <Empty icon={<Activity/>} title="No benchmark data in this range" text="Choose a wider time range or run the demo to add measured samples."/>}
        </section>}
        {page === 'IP Protection' && <IpProtectionView />}
        {page === 'Audit Trail' && <AuditView />}
        <footer className="footer"><div><Shield size={14}/> <b>CanaryWatch</b><span>TRAP, DON'T TRACK.</span></div><small>LOCAL DEMO · SYNTHETIC DATA · NOT A PRODUCTION SIEM</small></footer>
      </div>
    </main>
    {showResetConfirm && <div className="modal-backdrop" onClick={() => setShowResetConfirm(false)}><div className="modal" role="dialog" aria-modal="true" aria-labelledby="reset-title" onClick={event => event.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">CONTROLLED DEMO</span><h2 id="reset-title">Reset synthetic demo?</h2></div><button className="icon-button" aria-label="Close reset confirmation" disabled={busy} onClick={() => setShowResetConfirm(false)}>×</button></div><p className="modal-copy">This clears the current demo incidents and custom honeytokens, then restores the four baseline synthetic honeytokens. This cannot be undone.</p><div className="modal-actions"><button className="button secondary" disabled={busy} onClick={() => setShowResetConfirm(false)}>Cancel</button><button className="button primary" disabled={busy} onClick={reset}><RotateCcw size={15}/>{busy ? 'Resetting…' : 'Reset demo'}</button></div></div></div>}
    {showCreate && <div className="modal-backdrop" onClick={() => setShowCreate(false)}><div className="modal" onClick={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">DECEPTION ASSET</span><h2>Create honeytoken</h2></div><button className="icon-button" onClick={() => setShowCreate(false)}>×</button></div><p className="modal-copy">Create a synthetic decoy for the controlled demo environment.</p><label>Name<input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Payroll API canary"/></label><label>Artifact type<select value={kind} onChange={e => setKind(e.target.value)}>{['API credential','Config file','Cloud object','Database record','Sensitive document'].map(x => <option key={x}>{x}</option>)}</select></label><label>Severity<select value={severity} onChange={e => setSeverity(e.target.value)}>{['low','medium','high','critical'].map(x => <option key={x}>{x}</option>)}</select></label><div className="modal-actions"><button className="button secondary" onClick={() => setShowCreate(false)}>Cancel</button><button className="button primary" disabled={!name.trim() || busy} onClick={createToken}><Plus size={15}/> Create asset</button></div></div></div>}
  </div>
}
function Metric({icon,label,value,foot,tone}:{icon:React.ReactNode;label:string;value:React.ReactNode;foot:string;tone:string}) { return <div className="metric-card"><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}>{icon}</span></div><strong>{value}</strong><small>{foot}</small></div> }
function PanelTitle({title,sub,action,onAction}:{title:string;sub:string;action?:string;onAction?:()=>void}) { return <div className="panel-title"><div><h2>{title}</h2><p>{sub}</p></div>{action && <button onClick={onAction} className="text-action">{action}<ArrowUpRight size={14}/></button>}</div> }
function Empty({icon,title,text}:{icon:React.ReactNode;title:string;text:string}) { return <div className="empty-state"><span>{icon}</span><b>{title}</b><p>{text}</p></div> }
function Integration({icon,title,status,text}:{icon:React.ReactNode;title:string;status:string;text:string}) { return <div className="integration-card"><span className="integration-icon">{icon}</span><div className="integration-head"><h3>{title}</h3><span className="status neutral">{status}</span></div><p>{text}</p><button className="text-action" onClick={() => alert('This provider is not connected in the local demo.')}>View adapter details <ArrowUpRight size={14}/></button></div> }
function AuditView() {
  const [items, setItems] = useState<AuditEvent[]>([])
  const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    try {
      setItems(await api<AuditEvent[]>('/api/v1/audit'))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load the audit trail')
    }
  }, [])
  useEffect(() => { void refresh() }, [refresh])
  return <section className="panel table-panel"><PanelTitle title="Audit trail" sub="Application activity records" action="REFRESH" onAction={refresh}/>{error && <div className="error-banner"><AlertTriangle size={16}/><span>{error}</span></div>}{items.length ? items.map(x => <div className="audit-row" key={x.id}><CircleDot size={15}/><div><b>{x.action}</b><small>{x.target_id || 'System'} · {x.created_at}</small><p>{x.details}</p></div></div>) : !error && <Empty icon={<Archive/>} title="No audit entries" text="Actions will appear here when you create or trigger honeytokens."/ >}</section>
}
function IpProtectionView() {
  const [items, setItems] = useState<IpBlockEntry[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const refresh = useCallback(async () => {
    try {
      setItems(await api<IpBlockEntry[]>('/api/v1/ip-blocks'))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load IP protection records')
    }
  }, [])
  useEffect(() => { void refresh() }, [refresh])
  const simulate = async () => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await api<{ ip_address: string; blocked: boolean; failed_attempts: number }>('/api/v1/demo/ip-protection/simulate', { method: 'POST' })
      setNotice(`${result.ip_address}: ${result.failed_attempts} failed attempts recorded; ${result.blocked ? 'trigger access is now blocked in this demo.' : 'additional attempts are needed to reach the threshold.'}`)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to simulate failed attempts')
    } finally {
      setBusy(false)
    }
  }
  const unblock = async (ip: string) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await api<IpBlockEntry>(`/api/v1/ip-blocks/${encodeURIComponent(ip)}/unblock`, { method: 'POST' })
      setNotice(`${ip} was unblocked and its failure count was reset.`)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to unblock IP address')
    } finally {
      setBusy(false)
    }
  }
  return <section className="panel table-panel">
    <PanelTitle title="Demo IP protection" sub="Reversible block for repeated failed simulated triggers" action="REFRESH" onAction={refresh}/>
    <div className="ip-protection-note"><Ban size={18}/><p>After 4 failed trigger attempts from the same direct client IP, this demo blocks further requests to the trigger endpoint. It does not block the device, network, or other app pages. Shared networks can share one IP.</p></div>
    <div className="ip-protection-actions"><button className="button primary" disabled={busy} onClick={simulate}><Ban size={15}/>{busy ? 'Working…' : 'Simulate 4 failed attempts from this browser'}</button><span>Simulation is safe and only uses this browser’s connection address.</span></div>
    {error && <div className="error-banner"><AlertTriangle size={16}/><span>{error}</span></div>}
    {notice && <div className="toast"><Check size={16}/>{notice}</div>}
    {items.length === 0 ? <Empty icon={<ShieldCheck/>} title="No IPs tracked" text="Run the local simulation to demonstrate the four-attempt protection rule."/> : items.map(item => <div className="ip-block-row" key={item.ip_address}>
      <div className="incident-info"><b>{item.ip_address}</b><small>{item.failed_attempts} / 4 failed trigger attempts · last seen {formatLocalTime(item.updated_at)}</small></div>
      <div className="incident-right"><span className={`status ${item.blocked ? 'revoked' : 'active'}`}>{item.blocked ? 'blocked' : 'tracking'}</span>{item.blocked && <button className="button secondary" disabled={busy} onClick={() => unblock(item.ip_address)}>Unblock</button>}</div>
    </div>)}
  </section>
}
export default App
