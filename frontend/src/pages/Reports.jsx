import { useState, useEffect } from 'react'
import { fetchAPI } from '../utils/IDS_API'

export default function Reports() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAPI('/reports').then(res => {
      setData(res)
      setLoading(false)
    })
  }, [])

  if (loading) return <div style={{ padding: '100px', textAlign: 'center', color: '#64748b' }}>Generating Forensic Intelligence...</div>

  return (
    <div className="animate-in">
      <div className="page-intro">
        <div>
          <h2>Reports</h2>
          <p>Aggregated traffic intelligence and threat distribution analysis.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '32px' }}>
        <div className="dash-card">
          <div className="stat-label-premium">Total Packets</div>
          <div className="stat-value-premium">{data?.total_packets || 0}</div>
          <div style={{ color: 'var(--accent-green)', fontSize: '10px', marginTop: '4px' }}>↑ 12% FROM LAST HOUR</div>
        </div>
        <div className="dash-card">
          <div className="stat-label-premium">Threat Ratio</div>
          <div className="stat-value-premium">{data?.threat_percentage || 0}%</div>
          <div style={{ color: 'var(--accent-red)', fontSize: '10px', marginTop: '4px' }}>BASED ON NEURAL SCORE</div>
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

      <div className="dashboard-grid">
        <div className="main-column">
          <div className="dash-card">
            <h3 style={{ fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', marginBottom: '20px' }}>Top Attackers</h3>
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
                    <td><span style={{ color: a.avg_risk > 0.7 ? '#ef4444' : '#f59e0b' }}>{(a.avg_risk * 100).toFixed(0)}%</span></td>
                    <td>{a.max_pps}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="side-column">
            <div className="dash-card">
                <h3 style={{ fontSize: '11px', fontWeight: '800', textTransform: 'uppercase', marginBottom: '16px' }}>Decision Mix</h3>
                {Object.entries(data?.decisions || {}).map(([key, val]) => (
                    <div key={key} style={{ marginBottom: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontWeight: '700', marginBottom: '4px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>{key}</span>
                            <span>{val}</span>
                        </div>
                        <div style={{ height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                            <div style={{ 
                                height: '100%', 
                                width: `${(val / data.total_packets * 100).toFixed(0)}%`,
                                background: key === 'BLOCK' ? 'var(--accent-red)' : (key === 'ALLOW' ? 'var(--accent-green)' : 'var(--accent-orange)')
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
