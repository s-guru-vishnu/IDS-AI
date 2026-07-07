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

      <div className="dash-card" style={{ marginBottom: '24px', display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 200px', minWidth: '180px' }}>
              <label style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '800', display: 'block', marginBottom: '4px' }}>Filter by Source IP</label>
              <input 
                type="text" 
                placeholder="Enter the IP Address" 
                value={filters.source_ip}
                onChange={(e) => setFilters({...filters, source_ip: e.target.value})}
                style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px 14px', color: 'var(--text-primary)', outline: 'none', transition: 'border-color 0.2s' }}
                onFocus={(e) => e.target.style.borderColor = 'var(--accent-blue)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
              />
          </div>
          <div style={{ minWidth: '140px' }}>
              <label style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '800', display: 'block', marginBottom: '4px' }}>Decision</label>
              <select 
                value={filters.decision}
                onChange={(e) => setFilters({...filters, decision: e.target.value})}
                style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px 14px', color: 'var(--text-primary)', outline: 'none', width: '100%' }}
              >
                  <option value="all">ANY</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="ALLOW">ALLOW</option>
                  <option value="ALERT">ALERT</option>
              </select>
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
                <th>Attack Type</th>
                <th>Decision</th>
                <th>Final Risk</th>
              </tr>
            </thead>
            <tbody>
              {logs.length > 0 ? logs.map((log, i) => (
                <tr key={i}>
                  <td style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{log.Timestamp}</td>
                  <td style={{ fontWeight: '700', whiteSpace: 'nowrap' }}>{log.Source_IP}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{log.Dest_IP}</td>
                  <td style={{ color: log.Attack_Type !== 'Normal' ? 'var(--accent-red)' : 'var(--accent-green)', fontWeight: '700' }}>{log.Attack_Type}</td>
                  <td><span className={`badge-premium ${log.Decision === 'BLOCK' ? 'badge-block' : 'badge-allow'}`}>{log.Decision}</span></td>
                  <td style={{ fontWeight: '800' }}>{(log.Final_Risk * 100).toFixed(0)}%</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                    {loading ? 'Loading records...' : 'NO MATCHING RECORDS FOUND'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div style={{ padding: '20px', display: 'flex', justifyContent: 'center', gap: '12px', alignItems: 'center', borderTop: '1px solid var(--border-color)' }}>
            <button onClick={() => setPage(p => Math.max(1, p-1))} disabled={page <= 1} className="btn-3d" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', cursor: page > 1 ? 'pointer' : 'not-allowed', padding: '8px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '11px', color: 'var(--text-secondary)', opacity: page <= 1 ? 0.5 : 1 }}>PREV</button>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>PAGE {page}</span>
            <button onClick={() => setPage(p => p + 1)} disabled={logs.length < 50} className="btn-3d" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', cursor: logs.length >= 50 ? 'pointer' : 'not-allowed', padding: '8px 16px', borderRadius: '8px', fontWeight: 700, fontSize: '11px', color: 'var(--text-secondary)', opacity: logs.length < 50 ? 0.5 : 1 }}>NEXT</button>
        </div>
      </div>
    </div>
  )
}
