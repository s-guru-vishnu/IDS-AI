import { useState, useEffect } from 'react'
import { fetchAPI } from '../utils/IDS_API'

export default function Reports() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAPI('/reports').then(res => {
      setData(res)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="loading-screen">
      <div className="loading-spinner"></div>
      <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', letterSpacing: '2px' }}>GENERATING FORENSIC INTELLIGENCE...</div>
    </div>
  )

  const totalPackets = data?.total_packets || 0

  return (
    <div className="animate-in">
      <div className="page-intro">
        <div>
          <h2>Reports</h2>
          <p>Aggregated traffic intelligence and threat distribution analysis.</p>
        </div>
      </div>

      <div className="stagger-in" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 220px), 1fr))', gap: '24px', marginBottom: '32px' }}>
        <div className="dash-card">
          <div className="stat-label-premium">Total Packets</div>
          <div className="stat-value-premium">{totalPackets.toLocaleString()}</div>
          <div style={{ color: 'var(--accent-cyan)', fontSize: '10px', marginTop: '4px', fontWeight: 700 }}>AGGREGATE VOLUME</div>
        </div>
        <div className="dash-card">
          <div className="stat-label-premium">Threat Ratio</div>
          <div className="stat-value-premium">{data?.threat_percentage || 0}%</div>
          <div style={{ color: 'var(--accent-red)', fontSize: '10px', marginTop: '4px', fontWeight: 700 }}>BASED ON NEURAL SCORE</div>
        </div>
        <div className="dash-card">
          <div className="stat-label-premium">Avg Throughput</div>
          <div className="stat-value-premium">{data?.pps_stats?.avg_pps?.toFixed(1) || 0} <span style={{ fontSize: '12px' }}>PPS</span></div>
        </div>
        <div className="dash-card">
          <div className="stat-label-premium">Max Peak</div>
          <div className="stat-value-premium">{data?.pps_stats?.max_pps || 0} <span style={{ fontSize: '12px' }}>PPS</span></div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 400px), 1fr))', gap: '24px' }}>
          <div className="dash-card">
            <h3 style={{ fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', marginBottom: '20px', letterSpacing: '1.5px', color: 'var(--text-muted)' }}>Top Attackers</h3>
            <div className="table-scroll">
              <table className="premium-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Threat Count</th>
                    <th>Avg Risk</th>
                    <th>Peak PPS</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.top_attackers?.map((a, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: '700' }}>{a.ip}</td>
                      <td>{a.threat_count}</td>
                      <td><span style={{ color: a.avg_risk > 0.7 ? 'var(--accent-red)' : 'var(--accent-orange)', fontWeight: 800 }}>{(a.avg_risk * 100).toFixed(0)}%</span></td>
                      <td>{a.max_pps}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="dash-card">
              <h3 style={{ fontSize: '11px', fontWeight: '800', textTransform: 'uppercase', marginBottom: '16px', letterSpacing: '1.5px', color: 'var(--text-muted)' }}>Decision Mix</h3>
              {Object.entries(data?.decisions || {}).map(([key, val]) => (
                  <div key={key} style={{ marginBottom: '16px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontWeight: '700', marginBottom: '6px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>{key}</span>
                          <span style={{ fontWeight: 800 }}>{val.toLocaleString()}</span>
                      </div>
                      <div style={{ height: '6px', background: 'var(--bg-surface)', borderRadius: '4px', overflow: 'hidden' }}>
                          <div style={{ 
                              height: '100%', 
                              width: `${totalPackets > 0 ? (val / totalPackets * 100).toFixed(0) : 0}%`,
                              background: key === 'BLOCK' ? 'var(--accent-red)' : (key === 'ALLOW' ? 'var(--accent-green)' : 'var(--accent-orange)'),
                              borderRadius: '4px',
                              transition: 'width 0.8s ease'
                          }}></div>
                      </div>
                  </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  )
}
