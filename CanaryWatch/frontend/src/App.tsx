import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertCircle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Command,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  LockKeyhole,
  Radar,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  Waves,
  Zap,
} from 'lucide-react';
import './App.css';

type Decoy = {
  id: string;
  name: string;
  decoy_type: string;
  deployment_location: string;
  is_active: boolean;
  hits_count: number;
};

type Event = {
  id: string;
  attacker_ip: string;
  geo_location: string;
  asn_org: string;
  request_path: string;
  severity: string;
  timestamp: string;
};

type Incident = {
  id: string;
  title: string;
  attacker_ip: string;
  status: string;
  containment_action: string;
  risk_score: number;
  created_at: string;
};

type DashboardData = {
  decoys: Decoy[];
  events: Event[];
  incidents: Incident[];
};

type GoogleUser = {
  email: string;
  name: string;
  picture?: string | null;
};

type GoogleCredentialResponse = {
  credential: string;
};

type GoogleIdentityApi = {
  initialize: (options: {
    client_id: string;
    callback: (response: GoogleCredentialResponse) => void;
    cancel_on_tap_outside?: boolean;
  }) => void;
  renderButton: (
    element: HTMLElement,
    options: {
      theme: 'outline';
      size: 'large';
      text: 'continue_with';
      shape: 'rectangular';
      logo_alignment: 'left';
      width: number;
    },
  ) => void;
};

declare global {
  interface Window {
    google?: { accounts: { id: GoogleIdentityApi } };
  }
}

const API_URL = 'http://127.0.0.1:8000';
const TOKEN_KEY = 'canarywatch_access_token';
const USER_KEY = 'canarywatch_user';
let googleScriptPromise: Promise<void> | null = null;

function loadGoogleIdentity(): Promise<void> {
  if (window.google) return Promise.resolve();
  if (googleScriptPromise) return googleScriptPromise;

  googleScriptPromise = new Promise((resolve, reject) => {
    let script = document.getElementById('google-identity-services') as HTMLScriptElement | null;
    if (!script) {
      script = document.createElement('script');
      script.id = 'google-identity-services';
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
    script.addEventListener('load', () => resolve(), { once: true });
    script.addEventListener(
      'error',
      () => reject(new Error('Google sign-in could not be loaded. Check your connection and try again.')),
      { once: true },
    );
  });
  return googleScriptPromise;
}

function GoogleSignInButton({
  clientId,
  onCredential,
  onError,
}: {
  clientId: string;
  onCredential: (credential: string) => void;
  onError: (message: string) => void;
}) {
  const buttonContainer = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let active = true;
    void loadGoogleIdentity()
      .then(() => {
        if (!active || !buttonContainer.current || !window.google) return;
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: (response) => onCredential(response.credential),
          cancel_on_tap_outside: false,
        });
        window.google.accounts.id.renderButton(buttonContainer.current, {
          theme: 'outline',
          size: 'large',
          text: 'continue_with',
          shape: 'rectangular',
          logo_alignment: 'left',
          width: Math.min(buttonContainer.current.clientWidth, 360),
        });
      })
      .catch((error: unknown) => {
        onError(error instanceof Error ? error.message : 'Google sign-in could not be loaded.');
      });

    return () => {
      active = false;
      buttonContainer.current?.replaceChildren();
    };
  }, [clientId, onCredential, onError]);

  return <div className="google-button-container" ref={buttonContainer} />;
}

function LoginScreen({
  clientId,
  configLoading,
  configError,
  loginError,
  loggingIn,
  onCredential,
  onError,
}: {
  clientId: string;
  configLoading: boolean;
  configError: string;
  loginError: string;
  loggingIn: boolean;
  onCredential: (credential: string) => void;
  onError: (message: string) => void;
}) {
  return (
    <main className="login-page">
      <div className="login-ambient ambient-one" />
      <div className="login-ambient ambient-two" />
      <a className="login-brand" href="#login" aria-label="CanaryWatch">
        <span className="brand-mark"><Shield size={22} strokeWidth={2.2} /></span>
        <span className="brand-name">canary<span>watch</span><small>DECEPTION MESH</small></span>
      </a>
      <div className="login-layout">
        <section className="login-story">
          <div className="login-kicker"><span className="live-dot" />SECURITY OPERATIONS CENTER</div>
          <h1>Stay a step<br />ahead of the <span>unexpected.</span></h1>
          <p>Sign in to your CanaryWatch workspace and keep a quiet eye on the signals that matter.</p>
          <div className="login-feature-list">
            <div><span><Radar size={17} /></span><strong>Deception, always on</strong><small>Know when a decoy gets touched.</small></div>
            <div><span><Fingerprint size={17} /></span><strong>Evidence, connected</strong><small>Follow a signal from trigger to incident.</small></div>
            <div><span><ShieldCheck size={17} /></span><strong>Your workspace, protected</strong><small>Sign in securely with your Google account.</small></div>
          </div>
        </section>
        <section className="login-card">
          <div className="login-card-mark"><ShieldCheck size={20} /></div>
          <p className="login-card-eyebrow">WELCOME TO CANARYWATCH</p>
          <h2>Sign in to your workspace</h2>
          <p className="login-card-copy">Use your organization’s Google account to continue.</p>
          {configError || loginError ? (
            <div className="login-error" role="alert"><AlertCircle size={16} /><span>{loginError || configError}</span></div>
          ) : null}
          {configLoading ? (
            <div className="google-button-placeholder"><RefreshCw size={16} className="spinning" />Connecting securely…</div>
          ) : clientId ? (
            <>
              <div className={`google-button-slot ${loggingIn ? 'is-loading' : ''}`}>
                <GoogleSignInButton clientId={clientId} onCredential={onCredential} onError={onError} />
                {loggingIn && <span className="google-button-overlay"><RefreshCw size={15} className="spinning" />Verifying with Google…</span>}
              </div>
              <div className="login-divider"><span />SECURE AUTHENTICATION<span /></div>
            </>
          ) : (
            <div className="google-button-placeholder">
              <LockKeyhole size={16} />
              {configError ? 'Google sign-in is unavailable.' : 'Google sign-in needs an OAuth client ID.'}
            </div>
          )}
          <p className="login-terms">By continuing, you’ll sign in with Google’s secure identity service. CanaryWatch only receives your verified account profile.</p>
          <div className="login-security"><LockKeyhole size={13} /><span>Encrypted sign-in</span><span className="login-security-dot">·</span><span>No Google password stored</span></div>
        </section>
      </div>
      <footer className="login-footer"><span>© 2026 CanaryWatch</span><span><span className={`status-dot ${configError ? 'orange' : 'green'}`} />Local CanaryWatch instance</span></footer>
    </main>
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Time unavailable';
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date);
}

function App() {
  const [accessToken, setAccessToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? '');
  const [user, setUser] = useState<GoogleUser | null>(() => {
    try {
      const storedUser = localStorage.getItem(USER_KEY);
      return storedUser ? (JSON.parse(storedUser) as GoogleUser) : null;
    } catch {
      localStorage.removeItem(USER_KEY);
      return null;
    }
  });
  const [googleClientId, setGoogleClientId] = useState('');
  const [configLoading, setConfigLoading] = useState(true);
  const [configError, setConfigError] = useState('');
  const [loginError, setLoginError] = useState('');
  const [loggingIn, setLoggingIn] = useState(false);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [simulating, setSimulating] = useState(false);
  const [notice, setNotice] = useState('');

  const authorizedFetch = useCallback(
    (url: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      headers.set('Authorization', `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );

  const signOut = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setAccessToken('');
    setUser(null);
    setData(null);
  }, []);

  const handleGoogleCredential = useCallback(async (credential: string) => {
    setLoggingIn(true);
    setLoginError('');
    try {
      const response = await fetch(`${API_URL}/api/auth/google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential }),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail ?? `Google sign-in failed (${response.status}).`);
      }
      const signedInUser = result.user as GoogleUser;
      localStorage.setItem(TOKEN_KEY, result.access_token as string);
      localStorage.setItem(USER_KEY, JSON.stringify(signedInUser));
      setUser(signedInUser);
      setAccessToken(result.access_token as string);
    } catch (loginFailure) {
      setLoginError(
        loginFailure instanceof Error ? loginFailure.message : 'Google sign-in could not be completed.',
      );
    } finally {
      setLoggingIn(false);
    }
  }, []);

  const handleGoogleError = useCallback((message: string) => setConfigError(message), []);

  useEffect(() => {
    let active = true;
    void fetch(`${API_URL}/api/auth/google/config`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`Could not load sign-in settings (${response.status}).`);
        return (await response.json()) as { enabled: boolean; client_id: string | null };
      })
      .then((config) => {
        if (active && config.enabled && config.client_id) setGoogleClientId(config.client_id);
      })
      .catch((configFailure: unknown) => {
        if (active) {
          setConfigError(
            configFailure instanceof Error ? configFailure.message : 'Could not load Google sign-in settings.',
          );
        }
      })
      .finally(() => {
        if (active) setConfigLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const loadDashboard = useCallback(async () => {
    if (!accessToken) return;
    setLoading(true);
    setError('');
    try {
      const [decoysResponse, eventsResponse, incidentsResponse] = await Promise.all([
        authorizedFetch(`${API_URL}/api/decoys/`),
        authorizedFetch(`${API_URL}/api/events/`),
        authorizedFetch(`${API_URL}/api/incidents/`),
      ]);
      const failedResponse = [decoysResponse, eventsResponse, incidentsResponse].find(
        (response) => !response.ok,
      );
      if (failedResponse) {
        if (failedResponse.status === 401) signOut();
        throw new Error(`The API returned ${failedResponse.status}. Please try again.`);
      }
      const [decoys, events, incidents] = await Promise.all([
        decoysResponse.json() as Promise<Decoy[]>,
        eventsResponse.json() as Promise<Event[]>,
        incidentsResponse.json() as Promise<Incident[]>,
      ]);
      setData({ decoys, events, incidents });
    } catch (loadError) {
      setError(
        loadError instanceof Error
          ? loadError.message
          : 'Unable to load security data. Please try again.',
      );
    } finally {
      setLoading(false);
    }
  }, [accessToken, authorizedFetch, signOut]);

  useEffect(() => {
    if (accessToken) void loadDashboard();
  }, [accessToken, loadDashboard]);

  const recentEvents = useMemo(
    () =>
      [...(data?.events ?? [])]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 5),
    [data],
  );

  const recentIncidents = useMemo(
    () =>
      [...(data?.incidents ?? [])]
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 4),
    [data],
  );

  const activityDays = useMemo(() => {
    const now = new Date();
    return Array.from({ length: 7 }, (_, index) => {
      const date = new Date(now);
      date.setDate(now.getDate() - (6 - index));
      const dayEvents = (data?.events ?? []).filter((event) => {
        const eventDate = new Date(event.timestamp);
        return (
          eventDate.getFullYear() === date.getFullYear() &&
          eventDate.getMonth() === date.getMonth() &&
          eventDate.getDate() === date.getDate()
        );
      });
      return {
        label: new Intl.DateTimeFormat('en', { weekday: 'short' }).format(date),
        count: dayEvents.length,
      };
    });
  }, [data]);

  const activeIncidents = (data?.incidents ?? []).filter(
    (incident) => !['resolved', 'closed'].includes(incident.status.toLowerCase()),
  ).length;
  const activeDecoys = (data?.decoys ?? []).filter((decoy) => decoy.is_active).length;
  const totalHits = (data?.decoys ?? []).reduce((total, decoy) => total + decoy.hits_count, 0);
  const maxActivity = Math.max(1, ...activityDays.map((day) => day.count));
  const hasActivity = (data?.events.length ?? 0) > 0;
  const apiConnected = Boolean(data && !error);

  const runSimulation = async () => {
    setSimulating(true);
    setNotice('');
    try {
      const response = await authorizedFetch(`${API_URL}/api/demo/simulate-attack`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(`Simulation failed with HTTP ${response.status}.`);
      }
      await loadDashboard();
      setNotice('Simulation complete. New telemetry is now reflected in your dashboard.');
    } catch (simulationError) {
      setError(
        simulationError instanceof Error
          ? simulationError.message
          : 'The attack simulation could not be completed.',
      );
    } finally {
      setSimulating(false);
    }
  };

  if (!accessToken) {
    return (
      <LoginScreen
        clientId={googleClientId}
        configLoading={configLoading}
        configError={configError}
        loginError={loginError}
        loggingIn={loggingIn}
        onCredential={handleGoogleCredential}
        onError={handleGoogleError}
      />
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" aria-label="CanaryWatch overview">
          <span className="brand-mark"><Shield size={22} strokeWidth={2.2} /></span>
          <span className="brand-name">canary<span>watch</span><small>DECEPTION MESH</small></span>
        </a>

        <div className="workspace-switcher">
          <span className="workspace-icon"><Command size={16} /></span>
          <span className="workspace-copy"><strong>Acme Security</strong><small>Workspace</small></span>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <p className="nav-label">WORKSPACE</p>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#overview"><LayoutDashboard size={17} />Overview</a>
          <a className="nav-item" href="#incidents"><Siren size={17} />Incidents<span className="nav-count">{activeIncidents}</span></a>
          <a className="nav-item" href="#activity"><Waves size={17} />Event stream</a>
          <a className="nav-item" href="#decoys"><Fingerprint size={17} />Deception assets</a>
        </nav>

        <p className="nav-label nav-label-spaced">MANAGE</p>
        <nav className="side-nav" aria-label="Management navigation">
          <a className="nav-item" href="#coverage"><Radar size={17} />Sensor coverage</a>
          <a className="nav-item" href="#activity"><LockKeyhole size={17} />Evidence vault</a>
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-tip">
            <span className="tip-icon"><Sparkles size={16} /></span>
            <strong>Quietly watching.</strong>
            <p>Your deception mesh is collecting signals around the clock.</p>
            <a href="#activity">View activity <ArrowRight size={13} /></a>
          </div>
          <button className="profile" type="button" onClick={signOut} title="Sign out of CanaryWatch">
            <span className="avatar">{user?.name.split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase() || 'CW'}</span>
            <span className="profile-copy"><strong>{user?.name || 'Signed in'}</strong><small>{user?.email || 'Google account'}</small></span>
            <span className="sign-out-label">Sign out</span>
          </button>
        </div>
      </aside>

      <main className="main-area" id="overview">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>Overview</strong></div>
          <div className="topbar-actions">
            <span className="environment-badge"><span />LOCAL INSTANCE</span>
            <button className="icon-button" aria-label="Notifications"><Bell size={17} /><i /></button>
            <button className="help-button"><CircleHelp size={16} />Help center</button>
          </div>
        </header>

        <div className="page-content">
          <section className="welcome-row">
            <div>
              <div className="eyebrow"><span className="live-dot" />SECURITY OPERATIONS CENTER</div>
              <h1>Good afternoon, {user?.name.split(' ')[0] || 'there'} <span className="wave">✳</span></h1>
              <p className="welcome-subtitle">Here’s what’s happening across your deception mesh.</p>
            </div>
            <div className="welcome-actions">
              <button className="secondary-button" onClick={() => void loadDashboard()} disabled={loading}>
                <RefreshCw size={15} className={loading ? 'spinning' : ''} />Refresh
              </button>
              <button className="primary-button" onClick={() => void runSimulation()} disabled={simulating}>
                {simulating ? <RefreshCw size={15} className="spinning" /> : <Zap size={15} />}
                {simulating ? 'Simulating…' : 'Run simulation'}
              </button>
            </div>
          </section>

          {error && (
            <div className="feedback error-feedback" role="alert">
              <AlertCircle size={17} /><span>{error}</span>
              <button onClick={() => void loadDashboard()}>Try again</button>
            </div>
          )}
          {notice && (
            <div className="feedback success-feedback" role="status">
              <Check size={17} /><span>{notice}</span>
              <button aria-label="Dismiss message" onClick={() => setNotice('')}>×</button>
            </div>
          )}

          <section className="stats-grid" aria-label="Security metrics">
            <article className="stat-card">
              <div className="stat-top"><span className="stat-icon mint"><Fingerprint size={18} /></span><span className="stat-caption">DEPLOYED</span><span className="stat-menu">···</span></div>
              <div className="stat-value">{data ? activeDecoys : loading ? <span className="skeleton" /> : '—'}</div>
              <div className="stat-bottom"><span className="stat-label">Active decoys</span><span className="stat-meta">{data ? `${data.decoys.length} deployed` : 'Live data'}</span></div>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span className="stat-icon blue"><Activity size={18} /></span><span className="stat-caption">ALL TIME</span><span className="stat-menu">···</span></div>
              <div className="stat-value">{data ? data.events.length : loading ? <span className="skeleton" /> : '—'}</div>
              <div className="stat-bottom"><span className="stat-label">Signals captured</span><span className="stat-meta"><ArrowUpRight size={13} />{totalHits} decoy hits</span></div>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span className="stat-icon amber"><ShieldAlert size={18} /></span><span className="stat-caption">NEEDS ATTENTION</span><span className="stat-menu">···</span></div>
              <div className="stat-value">{data ? activeIncidents : loading ? <span className="skeleton" /> : '—'}</div>
              <div className="stat-bottom"><span className="stat-label">Open incidents</span><span className="stat-meta">{activeIncidents > 0 ? <><span className="status-dot orange" />Investigate</> : <><ShieldCheck size={13} />All clear</>}</span></div>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span className="stat-icon lilac"><ShieldCheck size={18} /></span><span className="stat-caption">AUTOMATED</span><span className="stat-menu">···</span></div>
              <div className="stat-value">24<span className="stat-suffix">/7</span></div>
              <div className="stat-bottom"><span className="stat-label">Mesh monitoring</span><span className="stat-meta"><span className="status-dot green" />Operational</span></div>
            </article>
          </section>

          <section className="overview-grid">
            <article className="panel activity-panel" id="activity">
              <div className="panel-heading">
                <div><h2>Signal activity</h2><p>Captured telemetry over the last 7 days</p></div>
                <button className="select-button">Last 7 days <ChevronDown size={14} /></button>
              </div>
              <div className="chart-summary"><strong>{data?.events.length ?? '—'}</strong><span>total signals</span><span className="chart-change"><ArrowUpRight size={14} /> Live telemetry</span></div>
              <div className="chart" role="img" aria-label="Daily telemetry signal activity over the last seven days">
                <div className="chart-y-labels"><span>{maxActivity}</span><span>{Math.ceil(maxActivity / 2)}</span><span>0</span></div>
                <div className={`chart-plot ${!hasActivity && !loading ? 'chart-empty' : ''}`}>
                  <div className="chart-gridline line-one" /><div className="chart-gridline line-two" /><div className="chart-gridline line-three" />
                  {data && !hasActivity ? (
                    <div className="chart-empty-message"><Waves size={18} /><span>No telemetry in the last 7 days</span></div>
                  ) : data ? <div className="bars">
                    {activityDays.map((day, index) => (
                      <div className="bar-column" key={`${day.label}-${index}`}>
                        <div className={`bar ${day.count > 0 ? 'bar-filled' : ''}`} style={{ height: `${Math.max(day.count ? 14 : 4, (day.count / maxActivity) * 100)}%` }} title={`${day.count} signals`} />
                        <span>{day.label}</span>
                      </div>
                    ))}
                  </div> : <div className="chart-empty-message"><Waves size={18} /><span>{loading ? 'Loading activity…' : 'Activity unavailable'}</span></div>}
                </div>
              </div>
            </article>

            <article className="panel coverage-panel" id="coverage">
              <div className="panel-heading">
                <div><h2>API health</h2><p>Backend connectivity at a glance</p></div>
                <button className="more-button" aria-label="More mesh health options">···</button>
              </div>
              <div className="health-score">
                <div className="health-ring"><div><strong>{apiConnected ? '3/3' : '—'}</strong><small>CHECKS</small></div></div>
                <div className="health-copy"><strong>{apiConnected ? 'Backend connected' : error ? 'Connection issue' : 'Checking connection'}</strong><span><span className={`status-dot ${apiConnected ? 'green' : 'orange'}`} />{apiConnected ? 'All dashboard APIs responding' : 'Waiting for API response'}</span></div>
              </div>
              <div className="health-list">
                <div><span className="health-service"><span className="service-icon"><Radar size={15} /></span>Decoy API</span><span className="service-state"><span className={`status-dot ${apiConnected ? 'green' : 'orange'}`} />{apiConnected ? 'Responding' : 'Unavailable'}</span></div>
                <div><span className="health-service"><span className="service-icon"><Server size={15} /></span>Telemetry API</span><span className="service-state"><span className={`status-dot ${apiConnected ? 'green' : 'orange'}`} />{apiConnected ? 'Responding' : 'Unavailable'}</span></div>
                <div><span className="health-service"><span className="service-icon"><LockKeyhole size={15} /></span>Incident API</span><span className="service-state"><span className={`status-dot ${apiConnected ? 'green' : 'orange'}`} />{apiConnected ? 'Responding' : 'Unavailable'}</span></div>
              </div>
              <div className="coverage-footer"><Globe2 size={14} />Connected to local CanaryWatch API <ArrowRight size={14} /></div>
            </article>
          </section>

          <section className="bottom-grid">
            <article className="panel events-panel">
              <div className="panel-heading">
                <div><h2>Recent signals</h2><p>Latest activity detected by your decoys</p></div>
                <a className="text-link" href="#activity">View event stream <ArrowRight size={14} /></a>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>ORIGIN</th><th>DETECTED ON</th><th>SEVERITY</th><th>TIME</th></tr></thead>
                  <tbody>
                    {loading && !data ? (
                      <tr><td colSpan={4} className="empty-row"><RefreshCw size={16} className="spinning" />Loading live signals…</td></tr>
                    ) : recentEvents.length ? recentEvents.map((event) => (
                      <tr key={event.id}>
                        <td><span className="origin-cell"><span className="origin-icon"><Globe2 size={15} /></span><span><strong>{event.attacker_ip}</strong><small>{event.geo_location || 'Location unavailable'}</small></span></span></td>
                        <td className="detected-cell">{event.request_path || 'Unknown path'}</td>
                        <td><span className={`severity-pill ${event.severity.toLowerCase()}`}>{event.severity}</span></td>
                        <td className="time-cell"><Clock3 size={13} />{formatTime(event.timestamp)}</td>
                      </tr>
                    )) : (
                      <tr><td colSpan={4} className="empty-row"><Waves size={17} />No signals yet. Your mesh is standing by.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </article>

            <article className="panel incidents-panel" id="incidents">
              <div className="panel-heading">
                <div><h2>Incidents</h2><p>Recent threats requiring attention</p></div>
                <a className="text-link" href="#incidents">See all <ArrowRight size={14} /></a>
              </div>
              <div className="incident-list">
                {loading && !data ? (
                  <div className="incident-empty"><RefreshCw size={16} className="spinning" />Loading incidents…</div>
                ) : recentIncidents.length ? recentIncidents.map((incident) => (
                  <div className="incident-item" key={incident.id}>
                    <span className={`incident-icon ${incident.risk_score >= 70 ? 'risk-high' : 'risk-medium'}`}><Siren size={16} /></span>
                    <div className="incident-copy"><strong>{incident.title}</strong><span>{incident.attacker_ip} · {formatTime(incident.created_at)}</span></div>
                    <span className={`risk-score ${incident.risk_score >= 70 ? 'risk-text-high' : ''}`}>{incident.risk_score}<small>RISK</small></span>
                  </div>
                )) : (
                  <div className="incident-empty"><ShieldCheck size={18} />No open incidents. Looking good.</div>
                )}
              </div>
              <div className="incident-footer"><span><span className="status-dot green" />Automated containment enabled</span><ArrowDownRight size={15} /></div>
            </article>
          </section>

          <section className="assets-strip" id="decoys">
            <div className="assets-intro"><span className="assets-icon"><Fingerprint size={18} /></span><div><h2>Deception assets</h2><p>Honeytokens quietly guarding your environment</p></div></div>
            <div className="asset-metrics">
            <div><strong>{data ? data.decoys.length : '—'}</strong><span>Assets deployed</span></div>
            <div><strong>{data ? activeDecoys : '—'}</strong><span>Currently active</span></div>
            <div><strong>{data ? totalHits : '—'}</strong><span>Total interactions</span></div>
            </div>
            <a href="#activity" className="asset-link">Explore assets <ArrowRight size={15} /></a>
          </section>

          <footer className="page-footer"><span>CanaryWatch <span>·</span> Deception Mesh</span><span><span className={`status-dot ${apiConnected ? 'green' : 'orange'}`} />{apiConnected ? 'All dashboard APIs responding' : 'Service connection unavailable'}</span></footer>
        </div>
      </main>
    </div>
  );
}

export default App;
