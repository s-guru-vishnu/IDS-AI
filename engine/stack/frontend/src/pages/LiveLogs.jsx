import { useState, useEffect } from 'react'
import { fetchAPI } from '../utils/IDS_API'

export default function LiveLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [paused, setPaused] = useState(false)

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
      setLogs(data.logs || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
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
                className="engine-status"
                style={{ cursor: 'pointer', border: 'none', background: paused ? 'var(--accent-red-soft)' : 'var(--accent-blue-soft)', color: paused ? 'var(--accent-red)' : 'var(--accent-blue)' }}
             >
                <div className="status-pulse" style={{ background: paused ? 'var(--accent-red)' : 'var(--accent-blue)' }}></div>
                {paused ? 'STREAM PAUSED' : 'LIVE STREAM ACTIVE'}
             </button>
        </div>
      </div>

      <div className="dash-card">
        <table className="premium-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Dest IP</th>
              <th>PPS</th>
              <th>Vector</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log, i) => (
              <tr key={i}>
                <td>{log.Timestamp?.split(' ')[1] || '---'}</td>
                <td style={{ fontWeight: '700' }}>{log.Source_IP}</td>
                <td style={{ color: 'var(--text-muted)' }}>{log.Dest_IP || 'INTERNAL-SRS'}</td>
                <td><span className="badge-premium" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)' }}>{log.PPS || '0'} <span style={{fontSize: '9px', opacity: 0.6}}>/s</span></span></td>
                <td><span style={{ fontWeight: '800', color: log.Attack_Type === 'Normal' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '11px' }}>{log.Attack_Type || '---'}</span></td>
                <td>
                  <span className={`badge-premium ${log.Decision === 'BLOCK' ? 'badge-block' : 'badge-allow'}`}>{log.Decision}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {loading && <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Syncing with interface...</div>}
      </div>
    </div>
  )
}
