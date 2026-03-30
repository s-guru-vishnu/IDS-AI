import { useState, useEffect } from 'react'
import { fetchAPI, getAttackColor } from '../utils/IDS_API'

export default function AlertLogs() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('all')
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => {
    loadAlerts()
    const interval = setInterval(loadAlerts, 5000)
    return () => clearInterval(interval)
  }, [severity])

  async function loadAlerts() {
    try {
      const data = await fetchAPI(`/alert-logs?severity=${severity}`)
      setAlerts(data.alerts || [])
    } catch (err) {
      console.error('Failed to load alerts:', err)
    } finally {
      setLoading(false)
    }
  }

  const toggleExpand = (idx) => {
    setExpandedId(expandedId === idx ? null : idx)
  }

  return (
    <div className="animate-in" style={{ paddingBottom: '60px' }}>
      <div className="page-intro">
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            Incident Response Ledger
            <span className="live-badge"><span></span> LIVE MONITOR</span>
          </h2>
          <p style={{ marginTop: '8px' }}>Consolidated security event notifications from multi-layer sensors.</p>
        </div>
        
        <div className="filter-group" style={{ display: 'flex', background: 'rgba(255,255,255,0.03)', padding: '4px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
            {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                <button 
                    key={s}
                    onClick={() => setSeverity(s)}
                    style={{ 
                        background: severity === s ? 'var(--accent-blue)' : 'transparent',
                        color: severity === s ? '#fff' : 'var(--text-muted)',
                        border: 'none',
                        cursor: 'pointer',
                        padding: '8px 16px',
                        fontSize: '10px',
                        fontWeight: '800',
                        borderRadius: '8px',
                        transition: 'all 0.2s ease',
                        textTransform: 'uppercase',
                        letterSpacing: '1px'
                    }}
                >
                    {s}
                </button>
            ))}
        </div>
      </div>

      <div className="dash-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-container">
            <table className="premium-table">
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '16px 20px' }}>Severity</th>
                  <th style={{ textAlign: 'left', padding: '16px' }}>Threat Type & Source</th>
                  <th style={{ textAlign: 'left', padding: '16px' }}>Detection Engine</th>
                  <th style={{ textAlign: 'center', padding: '16px' }}>Risk %</th>
                  <th style={{ textAlign: 'right', padding: '16px 20px' }}>Time Occurred</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length > 0 ? alerts.map((alert, idx) => {
                  const atkStyle = getAttackColor(alert.Attack_Type || alert.alert_type || '');
                  const isCritical = alert.severity === 'CRITICAL' || alert.severity === 'HIGH';
                  const isExpanded = expandedId === idx;
                  
                  return (
                    <tr key={idx} style={{ display: 'contents' }}>
                      <td colSpan="5" style={{ padding: 0 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <tbody>
                            <tr 
                              onClick={() => toggleExpand(idx)}
                              style={{ cursor: 'pointer', transition: 'background 0.2s', borderBottom: isExpanded ? 'none' : '1px solid var(--border-color)' }} 
                              className={`hover-row ${isExpanded ? 'active-row' : ''}`}
                            >
                              <td style={{ padding: '20px', width: '15%' }}>
                                 <span style={{ 
                                    fontSize: '9px', 
                                    fontWeight: '900', 
                                    background: isCritical ? 'rgba(220, 38, 38, 0.15)' : 'rgba(217, 119, 6, 0.15)',
                                    color: isCritical ? 'var(--accent-red)' : 'var(--accent-orange)',
                                    padding: '4px 10px',
                                    borderRadius: '20px',
                                    border: `1px solid ${isCritical ? 'rgba(220, 38, 38, 0.2)' : 'rgba(217, 119, 6, 0.2)'}`
                                  }}>
                                    {alert.severity}
                                  </span>
                              </td>
                              <td style={{ padding: '16px', width: '35%' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                   <div style={{ width: '32px', height: '32px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: atkStyle.bg, borderRadius: '8px' }}>
                                     <div style={{ width: '18px', height: '18px' }}>{atkStyle.icon}</div>
                                   </div>
                                   <div>
                                      <div style={{ fontWeight: '800', fontSize: '13px', color: 'var(--text-primary)' }}>{alert.Attack_Type || alert.alert_type || 'Potential Infiltration'}</div>
                                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: '2px' }}>{alert.Source_IP || alert.source_ip || '0.0.0.0'}</div>
                                   </div>
                                </div>
                              </td>
                              <td style={{ padding: '16px', width: '20%' }}>
                                 <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--accent-cyan)' }}>{alert.alert_source || 'AI-CORE'}</div>
                                 <div style={{ fontSize: '9px', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '2px' }}>{alert.alert_source === 'MITM' ? 'Hardware ARP Sensor' : 'Unified AI Engine V71'}</div>
                              </td>
                              <td style={{ padding: '16px', textAlign: 'center', width: '15%' }}>
                                 <div style={{ 
                                   fontSize: '14px', 
                                   fontWeight: '900', 
                                   color: isCritical ? 'var(--accent-red)' : 'var(--accent-orange)' 
                                 }}>
                                    {((alert.Final_Risk || alert.risk_score || 0) * 100).toFixed(0)}%
                                 </div>
                              </td>
                              <td style={{ padding: '20px', textAlign: 'right', width: '15%' }}>
                                 <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)' }}>{alert.Timestamp?.split(' ')[1] || alert.timestamp?.split(' ')[1] || 'Real-time'}</div>
                                 <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>{alert.Timestamp?.split(' ')[0] || alert.timestamp?.split(' ')[0] || 'Today'}</div>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                                <td colSpan="5" style={{ padding: '0 20px 20px 20px', background: 'rgba(255,255,255,0.01)' }}>
                                   <div className="xai-container" style={{ 
                                      background: 'rgba(0,0,0,0.2)', 
                                      padding: '20px', 
                                      borderRadius: '12px', 
                                      border: '1px solid rgba(255,255,255,0.05)',
                                      marginTop: '10px'
                                   }}>
                                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                                        <div style={{ fontSize: '11px', fontWeight: '900', color: 'var(--accent-cyan)', letterSpacing: '1px' }}>
                                          🧠 AI-IDS EXPLAINABILITY LAYER
                                        </div>
                                        <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                          Source: {alert.XAI_Source || 'Analytic Engine'}
                                        </div>
                                      </div>
                                      <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text-secondary)', margin: 0 }}>
                                        {alert.XAI_Explanation || "Generating AI narrative... (Wait 5-10 seconds for Groq analysis to complete)"}
                                      </p>
                                      {alert.Reasons && (
                                        <div style={{ marginTop: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                          {(typeof alert.Reasons === 'string' ? alert.Reasons.split('|') : (Array.isArray(alert.Reasons) ? alert.Reasons : [])).map((r, i) => (
                                            <span key={i} style={{ fontSize: '10px', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '4px', color: 'var(--text-muted)' }}>
                                              {r.trim()}
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                   </div>
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  )
                }) : !loading && (
                   <tr>
                     <td colSpan="5" style={{ padding: '100px', textAlign: 'center' }}>
                        <div style={{ opacity: 0.5, marginBottom: '20px' }}>
                           <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--accent-green)' }}>
                              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                              <polyline points="22 4 12 14.01 9 11.01" />
                           </svg>
                        </div>
                        <div style={{ fontSize: '12px', fontWeight: '800', color: 'var(--text-muted)', letterSpacing: '2px' }}>NO ACTIVE THREATS DETECTED</div>
                        <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.2)', marginTop: '8px' }}>Security systems are operating within normal parameters</div>
                     </td>
                   </tr>
                )}
              </tbody>
            </table>
          </div>
      </div>
      
      {loading && alerts.length === 0 && (
         <div style={{ marginTop: '40px', textAlign: 'center' }}>
            <div className="status-pulse" style={{ width: '30px', height: '30px', background: 'var(--accent-blue)', margin: '0 auto' }}></div>
            <div style={{ fontSize: '10px', fontWeight: '900', color: 'var(--text-muted)', marginTop: '16px', letterSpacing: '2px' }}>POLLING SECURITY DATABASE...</div>
         </div>
      )}
    </div>
  )
}
