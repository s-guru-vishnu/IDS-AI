import { useState, useEffect, useCallback } from 'react'
import { fetchAPI, API_BASE } from '../utils/IDS_API'

export default function BlockedIPs() {
  const [blocked, setBlocked] = useState([])
  const [firewallBlocks, setFirewallBlocks] = useState([])
  const [fwStats, setFwStats] = useState({ active_count: 0, expired_count: 0, total: 0 })
  const [loading, setLoading] = useState(true)
  const [unblocking, setUnblocking] = useState(null) // IP currently being unblocked

  const loadData = useCallback(() => {
    Promise.all([
      fetchAPI('/blocked-ips'),
      fetchAPI('/firewall-blocks').catch(() => ({ blocks: [], active_count: 0, expired_count: 0, total: 0 }))
    ]).then(([blockedRes, fwRes]) => {
      setBlocked(blockedRes.blocked_ips || [])
      setFirewallBlocks(fwRes.blocks || [])
      setFwStats({ active_count: fwRes.active_count || 0, expired_count: fwRes.expired_count || 0, total: fwRes.total || 0 })
      setLoading(false)
    })
  }, [])

  useEffect(() => {
    loadData()
    // Auto-refresh every 15 seconds for live TTL countdown
    const interval = setInterval(loadData, 15000)
    return () => clearInterval(interval)
  }, [loadData])

  const handleUnblock = async (ip) => {
    if (!window.confirm(`Are you sure you want to unblock ${ip}? This will remove the firewall rule immediately.`)) return
    setUnblocking(ip)
    try {
      const res = await fetch(`${API_BASE}/unblock-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      })
      const data = await res.json()
      if (data.success) {
        loadData() // Refresh
      } else {
        alert(data.error || 'Unblock failed')
      }
    } catch (err) {
      alert('Unblock request failed: ' + err.message)
    }
    setUnblocking(null)
  }

  const formatTTL = (seconds) => {
    if (!seconds || seconds <= 0) return '—'
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}m ${secs}s`
  }

  if (loading) return <div style={{ padding: '100px', textAlign: 'center', color: '#64748b' }}>Accessing Blacklist Registry...</div>

  return (
    <div className="animate-in">
      <div className="page-intro">
        <div>
          <h2>Blocked IPs</h2>
          <p>Blacklisted network entities currently denied system access by Defense Engine.</p>
        </div>
      </div>

      {/* ═══════ FIREWALL BLOCKS — Live OS-Level Blocks ═══════ */}
      <div className="dash-card" style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(220, 38, 38, 0.15), rgba(220, 38, 38, 0.05))',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px'
            }}>🔒</div>
            <div>
              <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 800, letterSpacing: '0.5px' }}>
                FIREWALL BLOCKS
              </h3>
              <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)' }}>
                OS-level firewall rules • Auto-expires after 10 minutes
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{
              padding: '4px 12px', borderRadius: '6px', fontSize: '11px', fontWeight: 800,
              background: fwStats.active_count > 0 ? 'rgba(220, 38, 38, 0.12)' : 'rgba(5, 150, 105, 0.1)',
              color: fwStats.active_count > 0 ? '#dc2626' : '#059669',
            }}>
              {fwStats.active_count} ACTIVE
            </div>
            <div style={{
              padding: '4px 12px', borderRadius: '6px', fontSize: '11px', fontWeight: 800,
              background: 'rgba(100, 116, 139, 0.08)', color: '#64748b',
            }}>
              {fwStats.expired_count} EXPIRED
            </div>
          </div>
        </div>

        <table className="premium-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Attack Vector</th>
              <th>Risk Score</th>
              <th>Blocked At</th>
              <th>TTL Remaining</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {firewallBlocks.map((block, i) => {
              const isActive = block.status === 'ACTIVE'
              return (
                <tr key={i} style={{ opacity: isActive ? 1 : 0.5 }}>
                  <td style={{ fontWeight: 800, color: isActive ? 'var(--accent-red)' : 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    {block.ip}
                  </td>
                  <td>
                    <span style={{
                      fontSize: '10px', fontWeight: 700, padding: '3px 8px', borderRadius: '4px',
                      background: 'rgba(220, 38, 38, 0.08)', color: '#ef4444'
                    }}>{block.reason}</span>
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 800 }}>
                    {(block.severity * 100).toFixed(0)}%
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {block.blocked_at}
                  </td>
                  <td>
                    {isActive ? (
                      <span style={{
                        fontFamily: 'JetBrains Mono', fontWeight: 800, fontSize: '12px',
                        color: '#dc2626', padding: '3px 8px', borderRadius: '4px',
                        background: 'rgba(220, 38, 38, 0.08)',
                        animation: 'pulse 2s infinite'
                      }}>
                        {formatTTL(block.remaining_seconds)}
                      </span>
                    ) : (
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        width: '8px', height: '8px', borderRadius: '50%',
                        background: isActive ? 'var(--accent-red)' : '#475569',
                        boxShadow: isActive ? '0 0 10px var(--accent-red)' : 'none',
                      }}></div>
                      <span style={{
                        fontSize: '10px', fontWeight: 800, letterSpacing: '0.5px',
                        color: isActive ? 'var(--accent-red)' : 'var(--text-muted)'
                      }}>
                        {isActive ? 'BLOCKED' : 'RELEASED'}
                      </span>
                    </div>
                  </td>
                  <td>
                    {isActive && (
                      <button
                        onClick={() => handleUnblock(block.ip)}
                        disabled={unblocking === block.ip}
                        style={{
                          padding: '4px 12px', borderRadius: '6px', fontSize: '10px', fontWeight: 800,
                          border: '1px solid rgba(220, 38, 38, 0.3)', cursor: 'pointer',
                          background: unblocking === block.ip ? 'rgba(100,100,100,.1)' : 'rgba(220, 38, 38, 0.06)',
                          color: '#dc2626', letterSpacing: '0.5px', transition: 'all 0.2s',
                        }}
                        onMouseOver={(e) => { e.target.style.background = 'rgba(220, 38, 38, 0.15)' }}
                        onMouseOut={(e) => { e.target.style.background = 'rgba(220, 38, 38, 0.06)' }}
                      >
                        {unblocking === block.ip ? 'RELEASING...' : 'UNBLOCK'}
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {firewallBlocks.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)', fontSize: '13px' }}>
            No firewall blocks active. All traffic permitted.
          </div>
        )}
      </div>

      {/* ═══════ DECISION ENGINE BLOCKS — Historical block records ═══════ */}
      <div className="dash-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '18px' }}>
          <div style={{
            width: '36px', height: '36px', borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.15), rgba(124, 58, 237, 0.05))',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px'
          }}>📋</div>
          <div>
            <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 800, letterSpacing: '0.5px' }}>
              BLOCK HISTORY
            </h3>
            <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-muted)' }}>
              All IPs flagged by the Decision Engine for blocking
            </p>
          </div>
        </div>

        <table className="premium-table">
          <thead>
            <tr>
              <th>Blocked IP Address</th>
              <th>Block Count</th>
              <th>Last Incident</th>
              <th>Avg Risk</th>
              <th>Primary Reasons</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {blocked.map((item, i) => (
              <tr key={i}>
                <td style={{ fontWeight: '800', color: 'var(--accent-red)' }}>{item.source_ip}</td>
                <td><span className="badge-premium" style={{ background: 'var(--accent-red-soft)', color: 'var(--accent-red)' }}>{item.block_count} EVENTS</span></td>
                <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{item.last_blocked}</td>
                <td style={{ fontFamily: 'JetBrains Mono', fontWeight: '800' }}>{(item.avg_risk * 100).toFixed(0)}%</td>
                <td>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {item.reasons?.map((r, idx) => (
                            <span key={idx} style={{ fontSize: '9px', padding: '2px 6px', background: 'rgba(255,255,255,0.03)', borderRadius: '3px' }}>{r.split('|')[0]}</span>
                        ))}
                    </div>
                </td>
                <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: '8px', height: '8px', background: 'var(--accent-red)', borderRadius: '50%', boxShadow: '0 0 8px var(--accent-red)' }}></div>
                        <span style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)' }}>TERMINATED</span>
                    </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {blocked.length === 0 && <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>No blacklisted entities found. Perimeter secure.</div>}
      </div>
    </div>
  )
}
