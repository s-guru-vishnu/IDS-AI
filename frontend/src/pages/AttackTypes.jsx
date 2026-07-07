import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { fetchAPI, getAttackColor } from '../utils/IDS_API'

export default function AttackTypes() {
  const { type: urlType } = useParams()
  const navigate = useNavigate()
  const [types, setTypes] = useState([])
  const [drilldown, setDrilldown] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [urlType])

  async function loadData() {
    setLoading(true)
    try {
      if (urlType) {
        const data = await fetchAPI(`/attack-types?type=${urlType}`)
        setDrilldown(data)
      } else {
        const data = await fetchAPI('/attack-types')
        setTypes(data.attack_types || [])
        setDrilldown(null)
      }
    } finally {
      setLoading(false)
    }
  }

  if (loading && !urlType) return (
    <div className="loading-screen">
      <div className="loading-spinner"></div>
      <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', letterSpacing: '2px' }}>ANALYZING ATTACK VECTORS...</div>
    </div>
  )

  return (
    <div className="animate-in">
      {!urlType ? (
        <>
          <div className="page-intro">
            <div>
              <h2>Attack Classification</h2>
              <p>Sophisticated multi-vector categorization based on behavioral heuristics and AI signatures.</p>
            </div>
          </div>

          <div className="stagger-in" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '24px' }}>
            {types.map((t, i) => {
              const theme = getAttackColor(t.attack_type);
              return (
                <div key={i} className="dash-card dash-card-mesh" style={{ cursor: 'pointer', borderLeft: `4px solid ${theme.color}` }} onClick={() => navigate(`/attack-types/${t.attack_type}`)}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', position: 'relative', zIndex: 1 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>{t.attack_type}</div>
                      <div style={{ fontSize: '36px', fontWeight: '800', color: 'var(--text-primary)', letterSpacing: '-1.5px' }}>{t.count.toLocaleString()}</div>
                    </div>
                  </div>
                  <div style={{ marginTop: '24px', padding: '16px', background: 'var(--bg-surface)', borderRadius: '12px', display: 'flex', justifyContent: 'space-between', position: 'relative', zIndex: 1 }}>
                      <div>
                          <div style={{ fontSize: '9px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Average Risk</div>
                          <div style={{ fontSize: '16px', fontWeight: '800', color: theme.color }}>{(t.avg_risk * 100).toFixed(1)}%</div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                          <div style={{ fontSize: '9px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Vectors</div>
                          <div style={{ fontSize: '16px', fontWeight: '800', color: 'var(--text-primary)' }}>{t.unique_ips}</div>
                      </div>
                  </div>
                </div>
              )
            })}
          </div>
        </>
      ) : (
        <>
          <div className="page-intro">
            <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
                <button 
                  onClick={() => navigate('/attack-types')} 
                  className="btn-3d"
                  style={{ 
                    padding: '10px 16px', border: '1px solid var(--border-color)', 
                    background: 'var(--bg-surface)', color: 'var(--text-primary)', 
                    fontSize: '11px', fontWeight: '800', cursor: 'pointer', borderRadius: '8px',
                    display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="19" y1="12" x2="5" y2="12"></line>
                    <polyline points="12 19 5 12 12 5"></polyline>
                  </svg>
                  BACK
                </button>
                <div>
                    <h2>{urlType} Deep-Dive</h2>
                    <p>Granular forensic analysis for the {urlType} threat vector.</p>
                </div>
            </div>
          </div>

          <div className="dashboard-grid">
              <div className="main-column">
                  <div className="dash-card" style={{ padding: 0, overflow: 'hidden' }}>
                      <div style={{ padding: '24px 24px 0' }}>
                        <h3 style={{ fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '24px', color: 'var(--text-muted)' }}>Incident Records</h3>
                      </div>
                      <div className="table-scroll">
                        <table className="premium-table" style={{ minWidth: '600px' }}>
                            <thead>
                                <tr>
                                    <th>Event Timestamp</th>
                                    <th>Source Vector (IP)</th>
                                    <th>Risk Profile</th>
                                    <th>Throughput</th>
                                    <th>Countermeasure</th>
                                </tr>
                            </thead>
                            <tbody>
                                {drilldown?.records?.map((r, i) => (
                                  <tr key={i}>
                                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{r.Timestamp}</td>
                                      <td style={{ fontWeight: '800', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>{r.Source_IP}</td>
                                      <td>
                                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                              <div style={{ height: '6px', width: '60px', background: 'var(--bg-surface)', borderRadius: '10px', overflow: 'hidden' }}>
                                                  <div style={{ width: `${r.Final_Risk * 100}%`, height: '100%', background: r.Final_Risk > 0.7 ? 'var(--accent-red)' : 'var(--accent-orange)', transition: 'width 0.4s' }}></div>
                                              </div>
                                              <span style={{ fontSize: '12px', fontWeight: '800' }}>{(r.Final_Risk * 100).toFixed(0)}%</span>
                                          </div>
                                      </td>
                                      <td>{r.PPS} <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>PPS</span></td>
                                      <td><span className={`badge-premium ${r.Decision === 'BLOCK' ? 'badge-block' : 'badge-allow'}`}>{r.Decision}</span></td>
                                  </tr>
                                ))}
                            </tbody>
                        </table>
                      </div>
                  </div>
              </div>
              
              <div className="side-column">
                  <div className="dash-card">
                      <h3 style={{ fontSize: '11px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '24px', color: 'var(--text-muted)' }}>Statistical Pulse</h3>
                      <div className="risk-meter-container">
                          <div className="risk-circle glow-pulse" style={{ width: '130px', height: '130px' }}>
                              <div className="label">Mean Risk</div>
                              <div className="value">{(drilldown?.stats?.avg_risk * 100 || 0).toFixed(0)}%</div>
                          </div>
                      </div>
                      <div style={{ marginTop: '32px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                          <div style={{ background: 'var(--bg-surface)', padding: '16px', borderRadius: '12px' }}>
                              <div style={{ fontSize: '9px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>Total Sample Set</div>
                              <div style={{ fontSize: '24px', fontWeight: '800' }}>{drilldown?.stats?.total?.toLocaleString()}</div>
                          </div>
                          <div style={{ background: 'var(--bg-surface)', padding: '16px', borderRadius: '12px', borderLeft: '4px solid var(--accent-red)' }}>
                              <div style={{ fontSize: '9px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>Peak Threat Intensity</div>
                              <div style={{ fontSize: '24px', fontWeight: '800', color: 'var(--accent-red)' }}>{(drilldown?.stats?.max_risk * 100 || 0).toFixed(0)}%</div>
                          </div>
                      </div>
                  </div>
              </div>
          </div>
        </>
      )}
    </div>
  )
}
