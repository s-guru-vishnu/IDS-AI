import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fetchAPI } from '../utils/IDS_API'

export default function History() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initialDecision = searchParams.get('decision') || 'all'
  
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
      source_ip: '',
      attack_type: 'all',
      decision: initialDecision === 'any' ? 'all' : initialDecision
  })

  useEffect(() => {
    loadHistory()
  }, [page, filters])

  // Sync state back to URL if it changes via UI
  useEffect(() => {
    const newParams = new URLSearchParams(searchParams)
    if (filters.decision === 'all') {
      newParams.set('decision', 'any')
    } else {
      newParams.set('decision', filters.decision)
    }
    setSearchParams(newParams, { replace: true })
  }, [filters.decision])

  async function loadHistory() {
    setLoading(true)
    try {
      const query = new URLSearchParams({
        page,
        source_ip: filters.source_ip,
        attack_type: filters.attack_type,
        decision: filters.decision
      })
      const data = await fetchAPI(`/history?${query}`)
      setLogs(data.logs || [])
      setTotal(data.total || 0)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="animate-in">
      <div className="page-intro">
        <div>
          <h2>History</h2>
          <p>Complete historical archive of network interactions and decisions.</p>
        </div>
      </div>

      <div className="dash-card" style={{ marginBottom: '24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ flex: 1 }}>
              <label style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '800', display: 'block', marginBottom: '4px' }}>Filter by Source IP</label>
              <input 
                type="text" 
                placeholder="Enter the IP Address" 
                value={filters.source_ip}
                onChange={(e) => setFilters({...filters, source_ip: e.target.value})}
                style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-primary)', outline: 'none' }}
              />
          </div>
          <div>
              <label style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '800', display: 'block', marginBottom: '4px' }}>Decision</label>
              <select 
                value={filters.decision}
                onChange={(e) => setFilters({...filters, decision: e.target.value})}
                style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-primary)', outline: 'none' }}
              >
                  <option value="all">ANY</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="ALLOW">ALLOW</option>
                  <option value="ALERT">ALERT</option>
              </select>
          </div>
          
      </div>

      <div className="dash-card">
        <table className="premium-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Dest IP</th>
              <th>Attack Type</th>
              <th>Decision</th>
              <th>Final Risk</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log, i) => (
              <tr key={i}>
                <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{log.Timestamp}</td>
                <td style={{ fontWeight: '700' }}>{log.Source_IP}</td>
                <td>{log.Dest_IP}</td>
                <td style={{ color: log.Attack_Type !== 'Normal' ? '#ef4444' : 'var(--accent-green)', fontWeight: '700' }}>{log.Attack_Type}</td>
                <td><span className={`badge-premium ${log.Decision === 'BLOCK' ? 'badge-block' : 'badge-allow'}`}>{log.Decision}</span></td>
                <td style={{ fontWeight: '800' }}>{(log.Final_Risk * 100).toFixed(0)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
        
        <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'center', gap: '12px', alignItems: 'center' }}>
            <button onClick={() => setPage(p => Math.max(1, p-1))} className="nav-item" style={{ background: 'rgba(255,255,255,0.05)', border: 'none', cursor: 'pointer' }}>PREV</button>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>PAGE {page}</span>
            <button onClick={() => setPage(p => p + 1)} className="nav-item" style={{ background: 'rgba(255,255,255,0.05)', border: 'none', cursor: 'pointer' }}>NEXT</button>
        </div>
      </div>
    </div>
  )
}
