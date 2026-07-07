import { useState, useEffect, useRef } from 'react'
import { fetchAPI } from '../utils/IDS_API'

export default function LiveLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [paused, setPaused] = useState(false)
  const prevLogsRef = useRef([])

  useEffect(() => {
    let interval;
    if (!paused) {
      loadLogs()
      interval = setInterval(loadLogs, 2000)
    }
    return () => clearInterval(interval)
  }, [paused])

  async function loadLogs() {
    try {
      const data = await fetchAPI('/live-logs?limit=50')
      const newLogs = data.logs || []
      prevLogsRef.current = newLogs
      setLogs(newLogs)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getDecisionStyle = (decision) => {
    switch(decision) {
      case 'BLOCK': return { background: 'var(--accent-red-soft)', color: 'var(--accent-red)' }
      case 'ALERT': return { background: 'var(--accent-orange-soft)', color: 'var(--accent-orange)' }
      case 'THROTTLE': return { background: 'var(--accent-purple-soft)', color: 'var(--accent-purple)' }
      default: return { background: 'var(--accent-green-soft)', color: 'var(--accent-green)' }
    }
  }

  return (
    <div className="animate-in">
      <div className="page-intro">
        <div>
          <h2>Live Logs</h2>
          <p>Real-time packet stream and neural evaluation. Monitoring 50 most recent vectors.</p>
        </div>
        <div className="nav-right">
             <button 
                onClick={() => setPaused(!paused)}
                className="engine-status btn-3d"
                style={{ cursor: 'pointer', border: 'none', background: paused ? 'var(--accent-red-soft)' : 'var(--accent-blue-soft)', color: paused ? 'var(--accent-red)' : 'var(--accent-blue)' }}
             >
                <div className="status-pulse" style={{ background: paused ? 'var(--accent-red)' : 'var(--accent-blue)' }}></div>
                {paused ? 'STREAM PAUSED' : 'LIVE STREAM ACTIVE'}
             </button>
        </div>
      </div>

      <div className="dash-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-scroll">
          <table className="premium-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>PPS</th>
                <th>Risk</th>
                <th>Vector</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, i) => {
                const dStyle = getDecisionStyle(log.Decision)
                const risk = parseFloat(log.Final_Risk || 0)
                const riskColor = risk >= 0.8 ? 'var(--accent-red)' : risk >= 0.4 ? 'var(--accent-orange)' : 'var(--accent-green)'
                return (
                  <tr key={i} className={i < 3 && !paused ? 'row-new' : ''}>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{log.Timestamp?.split(' ')[1] || '---'}</td>
                    <td style={{ fontWeight: '700', whiteSpace: 'nowrap' }}>{log.Source_IP}</td>
                    <td style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{log.Dest_IP || 'INTERNAL-SRS'}</td>
                    <td>
                      <span className="badge-premium" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)' }}>
                        {log.PPS || '0'} <span style={{fontSize: '9px', opacity: 0.6}}>/s</span>
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: '800', fontSize: '12px', color: riskColor }}>
                        {(risk * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: '800', color: log.Attack_Type === 'Normal' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '11px' }}>
                        {log.Attack_Type || '---'}
                      </span>
                    </td>
                    <td>
                      <span className="badge-premium" style={dStyle}>{log.Decision}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {loading && <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Syncing with interface...</div>}
        {!loading && logs.length === 0 && (
          <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)', fontSize: '12px' }}>
            NO LIVE DATA — Engine may be offline
          </div>
        )}
      </div>
    </div>
  )
}
