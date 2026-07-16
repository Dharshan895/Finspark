import React, { useState, useEffect, useRef } from 'react';
import { 
  ResponsiveContainer, 
  AreaChart, Area, 
  BarChart, Bar, 
  XAxis, YAxis, 
  Tooltip, CartesianGrid 
} from 'recharts';
import { 
  Shield, 
  AlertTriangle, 
  Lock, 
  Unlock, 
  Play, 
  KeyRound, 
  Database, 
  FileText, 
  RefreshCw, 
  Eye, 
  CheckCircle,
  FileCode
} from 'lucide-react';

const BACKEND_HOST = window.location.hostname || 'localhost';
const API_URL = `http://${BACKEND_HOST}:8080/api`;
const WS_URL = `ws://${BACKEND_HOST}:8080/ws/events`;

export default function App() {
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [userRisks, setUserRisks] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [vaultStatus, setVaultStatus] = useState(null);
  const [decryptedAudit, setDecryptedAudit] = useState(null);
  const [showAlertBanner, setShowAlertBanner] = useState(false);
  const [lockedUser, setLockedUser] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState('feed'); // feed, audit, incidents
  const [loading, setLoading] = useState(false);

  const ws = useRef(null);

  // Connect to WebSocket
  useEffect(() => {
    connectWS();
    fetchInitialData();
    
    // Poll updates for user states & incidents
    const interval = setInterval(() => {
      fetchUserStates();
      fetchIncidents();
    }, 3000);

    return () => {
      if (ws.current) ws.current.close();
      clearInterval(interval);
    };
  }, []);

  const connectWS = () => {
    ws.current = new WebSocket(WS_URL);
    
    ws.current.onopen = () => {
      setIsConnected(true);
      console.log('Connected to SentinelIQ WebSocket');
    };

    ws.current.onclose = () => {
      setIsConnected(false);
      console.log('SentinelIQ WebSocket closed. Retrying...');
      setTimeout(connectWS, 3000);
    };

    ws.current.onerror = (err) => {
      console.error('WebSocket Error:', err);
    };

    ws.current.onmessage = (message) => {
      const event = JSON.parse(message.data);
      setEvents((prev) => {
        const updated = [event, ...prev];
        // Keep last 100 for rendering performance
        return updated.slice(0, 100);
      });

      // Auto-lock Detection
      if (event.user_status === 'locked' && event.risk_score >= 75) {
        setLockedUser(event.user_id);
        setShowAlertBanner(true);
      }

      // Sync risk state instantly if possible
      fetchUserStates();
      fetchIncidents();
    };
  };

  const fetchInitialData = () => {
    fetchUserStates();
    fetchIncidents();
    fetchVaultStatus();
  };

  const fetchUserStates = async () => {
    try {
      const res = await fetch(`${API_URL}/users/risk`);
      const data = await res.json();
      // Sort by cumulative risk score
      data.sort((a, b) => b.cumulative_risk - a.cumulative_risk);
      setUserRisks(data);
    } catch (e) {
      console.error('Error fetching user risk states:', e);
    }
  };

  const fetchIncidents = async () => {
    try {
      const res = await fetch(`${API_URL}/soar/incidents`);
      const data = await res.json();
      setIncidents(data);
    } catch (e) {
      console.error('Error fetching SOAR incidents:', e);
    }
  };

  const fetchVaultStatus = async () => {
    try {
      const res = await fetch(`${API_URL}/vault/status`);
      const data = await res.json();
      setVaultStatus(data);
    } catch (e) {
      console.error('Error fetching vault status:', e);
    }
  };

  const triggerAttack = async (type) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/trigger-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: type })
      });
      const data = await res.json();
      console.log('Demo Attack Triggered:', data);
    } catch (e) {
      console.error('Error triggering attack:', e);
    }
    setLoading(false);
  };

  const unlockUser = async (userId) => {
    try {
      const res = await fetch(`${API_URL}/unlock-user/${userId}`, { method: 'POST' });
      await res.json();
      fetchUserStates();
      fetchIncidents();
      // Dismiss banner if this user is unlocked
      if (lockedUser === userId) {
        setShowAlertBanner(false);
      }
    } catch (e) {
      console.error('Error unlocking user:', e);
    }
  };

  const decryptAuditTrail = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/audit-trail`);
      const data = await res.json();
      setDecryptedAudit(data);
      setActiveTab('audit');
    } catch (e) {
      console.error('Error decrypting audit log:', e);
    }
    setLoading(false);
  };

  // Recharts aggregations
  const getRiskTrendData = () => {
    // Take last 15 events, reverse to show chronological order
    const slice = [...events].slice(0, 15).reverse();
    return slice.map((e, idx) => ({
      index: idx + 1,
      risk: e.risk_score,
      user: e.user_id,
      action: e.action
    }));
  };

  const getRoleDistributionData = () => {
    const counts = { admin: 0, contractor: 0, vendor: 0, employee: 0 };
    events.forEach(e => {
      if (counts[e.role] !== undefined) {
        counts[e.role] += 1;
      }
    });
    return Object.keys(counts).map(role => ({
      role: role.toUpperCase(),
      Events: counts[role]
    }));
  };

  const getRiskCategory = (score) => {
    if (score >= 75) return 'high';
    if (score >= 36) return 'medium';
    return 'low';
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header>
        <div className="logo-section">
          <h1>🛡️ SentinelIQ</h1>
          <p>Autonomous Insider Threat Detection (UEBA & SOAR)</p>
        </div>
        <div className="metrics-summary">
          <div className="metric-card">
            <div className="metric-label">System State</div>
            <div className="metric-value" style={{ color: isConnected ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {isConnected ? 'PROTECTED' : 'OFFLINE'}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Total Events</div>
            <div className="metric-value">{events.length}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Anomalies</div>
            <div className="metric-value anomaly">
              {events.filter(e => e.risk_score >= 75).length}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Locked Users</div>
            <div className="metric-value locked">
              {userRisks.filter(u => u.status === 'locked').length}
            </div>
          </div>
        </div>
      </header>

      {/* Alert Banner */}
      {showAlertBanner && (
        <div className="alert-banner">
          <div className="alert-message">
            <AlertTriangle color="var(--accent-red)" size={24} />
            <span>SOAR TRIPPED: Privileged account <strong>{lockedUser}</strong> flagged for critical threat and automatically LOCKED.</span>
          </div>
          <button className="alert-dismiss-btn" onClick={() => setShowAlertBanner(false)}>
            Dismiss Alert
          </button>
        </div>
      )}

      {/* Main Grid */}
      <div className="dashboard-grid">
        {/* Left Column */}
        <div className="main-column">
          {/* Attack Panel Controls */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">
                <Play size={18} color="var(--accent-cyan)" /> Trigger Demo Scenarios (Inject Attacks)
              </span>
            </div>
            <div className="controls-row">
              <button className="btn btn-danger" onClick={() => triggerAttack(1)} disabled={loading}>
                Attack 1: Contractor Export (2 AM)
              </button>
              <button className="btn btn-danger" onClick={() => triggerAttack(2)} disabled={loading}>
                Attack 2: Admin Brute Force & Config
              </button>
              <button className="btn btn-danger" onClick={() => triggerAttack(3)} disabled={loading}>
                Attack 3: Vendor Privilege Abuse
              </button>
              <button className="btn btn-danger" onClick={() => triggerAttack(4)} disabled={loading}>
                Attack 4: Employee Data Hoarding
              </button>
              <button className="btn btn-danger" onClick={() => triggerAttack(5)} disabled={loading}>
                Attack 5: Impossible Travel Login
              </button>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button 
              className={`btn ${activeTab === 'feed' ? 'btn-primary' : ''}`}
              onClick={() => setActiveTab('feed')}
            >
              <RefreshCw size={16} /> Real-Time Telemetry Feed
            </button>
            <button 
              className={`btn ${activeTab === 'incidents' ? 'btn-primary' : ''}`}
              onClick={() => setActiveTab('incidents')}
            >
              <AlertTriangle size={16} /> SOAR Actions Log ({incidents.length})
            </button>
            <button 
              className={`btn ${activeTab === 'audit' ? 'btn-primary' : ''}`}
              onClick={() => decryptAuditTrail()}
              disabled={loading}
            >
              <Eye size={16} /> Decrypt & Inspect Audit Trail
            </button>
          </div>

          {/* Feed Content */}
          {activeTab === 'feed' && (
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Live Scrolling Operations Log</span>
                <span className="quantum-badge">AES-256 Flagged Logging Active</span>
              </div>
              <div className="feed-container">
                {events.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Waiting for WebSocket connection to stream banking operations...
                  </div>
                ) : (
                  events.map((e, idx) => {
                    const riskCat = getRiskCategory(e.risk_score);
                    return (
                      <div 
                        key={idx} 
                        className={`feed-item ${selectedEvent === e ? 'selected' : ''}`}
                        onClick={() => setSelectedEvent(e)}
                      >
                        <div className="timestamp">{e.timestamp.slice(11, 19)}</div>
                        <div className="user-id">{e.user_id}</div>
                        <div>
                          <span className={`role-badge ${e.role}`}>
                            {e.role}
                          </span>
                        </div>
                        <div className="action-text">{e.action}</div>
                        <div className="resource-text">{e.resource}</div>
                        <div>
                          <span className={`risk-badge ${riskCat}`}>
                            {e.risk_score}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* SOAR Incidents Tab */}
          {activeTab === 'incidents' && (
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Active SOAR Mitigations (Automated Incident Queue)</span>
              </div>
              <div className="feed-container">
                {incidents.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No SOAR security playbooks triggered yet. System operating normally.
                  </div>
                ) : (
                  incidents.map((t, idx) => (
                    <div key={idx} style={{ 
                      background: 'rgba(255, 51, 102, 0.05)', 
                      border: '1px solid var(--accent-red)', 
                      padding: '1rem', 
                      borderRadius: '8px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ color: 'var(--accent-red)' }}>{t.incident_id}</strong>
                        <span className="timestamp">{t.timestamp.slice(11, 19)}</span>
                      </div>
                      <div>
                        <strong>User:</strong> {t.user_id} ({t.role.toUpperCase()}) | <strong>Threat Score:</strong> {t.risk_score}/100
                      </div>
                      <div>
                        <strong>MITRE ATT&CK:</strong> {t.mitre_techniques.join(', ') || 'Unknown'}
                      </div>
                      <div style={{ background: 'var(--bg-primary)', padding: '0.5rem', borderRadius: '4px', fontStyle: 'italic', fontSize: '0.85rem' }}>
                        {t.explanation}
                      </div>
                      <div>
                        <strong>Automated Actions Executed:</strong>
                        <ul style={{ paddingLeft: '1.2rem', fontSize: '0.85rem', color: 'var(--accent-cyan)', marginTop: '4px' }}>
                          {t.actions_taken.map((act, aIdx) => (
                            <li key={aIdx}>{act}</li>
                          ))}
                        </ul>
                      </div>
                      {t.status === 'triggered' && (
                        <button 
                          className="btn btn-primary" 
                          style={{ alignSelf: 'flex-end', padding: '0.2rem 0.5rem', fontSize: '0.8rem' }}
                          onClick={() => unlockUser(t.user_id)}
                        >
                          <Unlock size={12} /> Override & Unlock User Account
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Audit Logs Tab */}
          {activeTab === 'audit' && (
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Decrypted Audit Logs (Decrypted Real-time)</span>
                <button className="btn" onClick={() => decryptAuditTrail()}>
                  <RefreshCw size={14} /> Refresh Trail
                </button>
              </div>
              <div className="feed-container">
                {!decryptedAudit ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Querying API for encrypted logs...
                  </div>
                ) : decryptedAudit.events.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No events written to audit trail. Only anomalous events (Risk &gt;= 50) are logged.
                  </div>
                ) : (
                  <div>
                    <div style={{ fontSize: '0.85rem', marginBottom: '1rem', color: 'var(--text-muted)' }}>
                      <strong>Encrypted File Size on Disk:</strong> {decryptedAudit.file_size_bytes} bytes | <strong>Records:</strong> {decryptedAudit.records_count}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {decryptedAudit.events.map((e, idx) => (
                        <div key={idx} style={{ 
                          background: 'var(--bg-tertiary)', 
                          border: '1px solid var(--border-color)', 
                          padding: '0.75rem', 
                          borderRadius: '6px' 
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            <span>{e.timestamp}</span>
                            <span>Risk Score: {e.risk_score}</span>
                          </div>
                          <div style={{ marginTop: '0.25rem' }}>
                            <strong>{e.user_id}</strong> ({e.role}) accessed <strong>{e.resource}</strong> via <strong>{e.action}</strong> ({e.volume_mb} MB)
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Charts Panel */}
          <div className="charts-grid">
            <div className="panel">
              <div className="panel-header"><span className="panel-title">Anomaly Risk Score Trend</span></div>
              <div style={{ width: '100%', height: 180 }}>
                <ResponsiveContainer>
                  <AreaChart data={getRiskTrendData()}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-red)" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="var(--accent-red)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="index" stroke="var(--text-muted)" fontSize={11} />
                    <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11} />
                    <Tooltip 
                      contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)' }}
                      labelStyle={{ color: 'var(--text-secondary)' }}
                    />
                    <Area type="monotone" dataKey="risk" stroke="var(--accent-red)" fillOpacity={1} fill="url(#colorRisk)" name="Risk Score" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="panel">
              <div className="panel-header"><span className="panel-title">Operations Count by Role</span></div>
              <div style={{ width: '100%', height: 180 }}>
                <ResponsiveContainer>
                  <BarChart data={getRoleDistributionData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="role" stroke="var(--text-muted)" fontSize={11} />
                    <YAxis stroke="var(--text-muted)" fontSize={11} />
                    <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)' }} />
                    <Bar dataKey="Events" fill="var(--accent-cyan)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Post Quantum Vault Status */}
          {vaultStatus && (
            <div className="panel" style={{ borderLeft: '3px solid var(--accent-cyan)' }}>
              <div className="panel-header">
                <span className="panel-title" style={{ color: 'var(--accent-cyan)' }}>
                  <KeyRound size={16} /> Quantum-Safe Vault
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div><strong>KEM Scheme:</strong> {vaultStatus.pqc_algorithm}</div>
                <div><strong>Symmetric Cipher:</strong> {vaultStatus.classic_algorithm}</div>
                <div><strong>Hybrid State:</strong> <span style={{ color: 'var(--accent-green)', fontWeight: 'bold' }}>{vaultStatus.status}</span></div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.3' }}>
                  * {vaultStatus.implementation_note}
                </div>
              </div>
            </div>
          )}

          {/* Drill Down Panel */}
          <div className="panel" style={{ flexGrow: 1 }}>
            <div className="panel-header">
              <span className="panel-title">
                <Database size={16} /> Investigation Panel
              </span>
            </div>
            
            {selectedEvent ? (
              <div className="drilldown-content">
                <div className="risk-dial-container">
                  <div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Anomalous Risk Index</div>
                    <div className="user-id" style={{ marginTop: '4px' }}>{selectedEvent.user_id}</div>
                  </div>
                  <div className={`risk-dial-score ${getRiskCategory(selectedEvent.risk_score)}`}>
                    {selectedEvent.risk_score}
                  </div>
                </div>

                <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                  <div><strong>Action:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedEvent.action}</span></div>
                  <div><strong>Target:</strong> <span style={{ wordBreak: 'break-all' }}>{selectedEvent.resource}</span></div>
                  <div><strong>Vol:</strong> {selectedEvent.volume_mb} MB</div>
                  <div><strong>Time:</strong> {selectedEvent.timestamp.slice(11, 19)} (Off-hours: {selectedEvent.is_off_hours ? 'Yes' : 'No'})</div>
                  <div><strong>Location:</strong> {selectedEvent.location}</div>
                  <div><strong>Status:</strong> {selectedEvent.user_status.toUpperCase()}</div>
                </div>

                {selectedEvent.risk_score >= 40 && (
                  <>
                    <div><strong>MITRE ATT&CK Mapping:</strong></div>
                    <div className="mitre-tags">
                      {selectedEvent.mitre_techniques.map((m, idx) => (
                        <span key={idx} className="mitre-tag">
                          {m.id}: {m.name}
                        </span>
                      ))}
                      {selectedEvent.mitre_techniques.length === 0 && (
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>None matched</span>
                      )}
                    </div>

                    <div><strong>AI Explainability Analysis:</strong></div>
                    <div className={`explanation-box ${selectedEvent.risk_score >= 75 ? 'high' : ''}`}>
                      {selectedEvent.explanation}
                    </div>
                  </>
                )}

                <div><strong>Raw Session Event Schema:</strong></div>
                <pre className="raw-json">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            ) : (
              <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Select an event from the stream feed to view deep-dive analytics.
              </div>
            )}
          </div>

          {/* User Risk Board */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">UEBA User Scoreboard</span>
            </div>
            <div className="user-risk-list">
              {userRisks.map((u, idx) => (
                <div key={idx} className="user-risk-item">
                  <div className="user-risk-info">
                    <span className={`user-status-dot ${u.status === 'locked' ? 'locked' : ''}`} />
                    <div>
                      <div style={{ fontWeight: '600', fontSize: '0.85rem' }}>{u.user_id}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{u.role.toUpperCase()}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className={`risk-badge ${getRiskCategory(u.cumulative_risk)}`} style={{ padding: '0.15rem 0.4rem', fontSize: '0.75rem' }}>
                      {u.cumulative_risk}
                    </span>
                    {u.status === 'locked' && (
                      <button 
                        style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer' }}
                        onClick={() => unlockUser(u.user_id)}
                        title="Unlock User"
                      >
                        <Unlock size={14} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
