import { useState, useEffect } from 'react'
import { fetchAPI, getAttackColor } from '../utils/IDS_API'
import { 
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, Legend
} from 'recharts'

export default function Overview() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function loadData() {
    try {
      const result = await fetchAPI('/overview')
      setData(result)
      setError(null)
    } catch (err) {
      console.error('Failed to load overview:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (loading && !data) return (
    <div style={{ display: 'flex', height: '60vh', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '20px' }}>
      <div className="status-pulse" style={{ width: '40px', height: '40px', background: 'var(--accent-blue)' }}></div>
      <div style={{ fontSize: '12px', fontWeight: '800', color: 'var(--text-muted)', letterSpacing: '2px' }}>SYNCING STRATEGIC CORE...</div>
    </div>
  )

  if (error && !data) return (
    <div style={{ display: 'flex', height: '60vh', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '20px' }}>
      <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--accent-red)' }}>CONNECTION OFFLINE</div>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{error}</div>
    </div>
  )

  const avgRisk = (data?.risk_stats?.avg_risk * 100 || 0).toFixed(1)

  return (
    <div className="animate-in" style={{ paddingBottom: '60px' }}>
      <div className="page-intro">
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            System Intelligence
            <span className="live-badge"><span></span> REAL-TIME ENGINE</span>
          </h2>
          <p style={{ marginTop: '8px' }}>Executive command center for multi-vector threat mitigation.</p>
        </div>
      </div>

      {/* 1. COMPACT ATTACK SUMMARY (Top Bar) */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(6, 1fr)', 
        gap: '12px', 
        marginBottom: '24px' 
      }}>
        {data?.attack_summary?.map((atk, i) => (
          <div key={i} className="dash-card dash-card-mesh" style={{ padding: '12px 16px', borderLeft: `3px solid ${getAttackColor(atk.name).color}` }}>
            <div style={{ fontSize: '9px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '2px' }}>{atk.name}</div>
            <div style={{ fontSize: '18px', fontWeight: '800', color: 'var(--text-primary)' }}>{atk.packets} <span style={{fontSize: '10px', opacity: 0.5}}>PKTS</span></div>
          </div>
        ))}
      </div>

      {/* 2. DYNAMIC INTEL GRID (3 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr', gap: '24px', marginBottom: '24px' }}>
        
        {/* Protocol Graph */}
        <div className="dash-card dash-card-mesh" style={{ minHeight: '380px', background: 'var(--dash-card-gradient)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 className="section-title" style={{ margin: 0 }}>Protocols</h3>
            <span style={{ fontSize: '9px', color: 'var(--accent-blue)', fontWeight: '800' }}>TCP/UDP</span>
          </div>
          <div style={{ height: '280px', width: '100%', position: 'relative' }}>
            {data?.chart_data?.length > 0 ? (
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data.chart_data}>
                    <defs>
                      <linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip 
                      contentStyle={{ background: 'var(--bg-card)', border: 'none', borderRadius: '8px', fontSize: '10px' }}
                    />
                    <Area type="monotone" dataKey="tcp" stroke="var(--accent-blue)" strokeWidth={2} fill="url(#colorTcp)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="shimmer" style={{ width: '100%', height: '100%' }}></div>}
          </div>
        </div>

        {/* COMPACT RISK METER (Center) */}
        <div className="dash-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: 'var(--dash-card-gradient)' }}>
            <h3 className="section-title" style={{ marginBottom: '16px' }}>Threat Index</h3>
            <div className="risk-meter-container">
                <div className="risk-circle" style={{ 
                    width: '150px', height: '150px', 
                    border: '8px solid var(--accent-red-soft)', 
                    boxShadow: `0 0 40px ${avgRisk > 50 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)'}`,
                }}>
                    <div className="label">Composite</div>
                    <div className="value" style={{ 
                        fontSize: '36px', 
                        color: avgRisk > 80 ? 'var(--accent-red)' : (avgRisk > 40 ? 'var(--accent-orange)' : 'var(--accent-blue)')
                    }}>{avgRisk}%</div>
                    <div style={{ 
                        fontSize: '9px', fontWeight: '900', marginTop: '5px', letterSpacing: '2px',
                        color: avgRisk > 80 ? 'var(--accent-red)' : 'var(--accent-blue)'
                    }}>
                        {avgRisk > 80 ? 'EMERGENCY' : (avgRisk > 40 ? 'ELEVATED' : 'SECURE')}
                    </div>
                </div>
            </div>
        </div>

        {/* Vector Graph */}
        <div className="dash-card dash-card-mesh" style={{ minHeight: '380px', background: 'var(--dash-card-gradient)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 className="section-title" style={{ margin: 0 }}>Vectors</h3>
            <span style={{ fontSize: '9px', color: 'var(--accent-green)', fontWeight: '800' }}>IN/OUT</span>
          </div>
          <div style={{ height: '280px', width: '100%', position: 'relative' }}>
            {data?.chart_data?.length > 0 ? (
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data.chart_data}>
                    <defs>
                      <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-green)" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="var(--accent-green)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip 
                      contentStyle={{ background: 'var(--bg-card)', border: 'none', borderRadius: '8px', fontSize: '10px' }}
                    />
                    <Area type="monotone" dataKey="incoming" stroke="var(--accent-green)" strokeWidth={2} fill="url(#colorIn)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="shimmer" style={{ width: '100%', height: '100%' }}></div>}
          </div>
        </div>

      </div>

      {/* 4. PREMIUM TABLES SECTION (Stacked Vertically) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        
        {/* 1. Network Status (Report Table) */}
        <div className="dash-card">
           <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <div style={{ width: '4px', height: '16px', background: 'var(--accent-blue)', borderRadius: '4px' }}></div>
              <h3 className="section-title" style={{ margin: 0 }}>Network Infrastructure Report</h3>
           </div>
           <div className="table-container">
             <table className="premium-table">
               <thead>
                 <tr>
                   <th style={{ textAlign: 'left', padding: '12px 16px' }}>Network Metric</th>
                   <th style={{ textAlign: 'right', padding: '12px 16px' }}>Current Value</th>
                   <th style={{ textAlign: 'center', padding: '12px 16px' }}>Status</th>
                 </tr>
               </thead>
               <tbody>
                 {data?.report_summary?.map((row, i) => (
                   <tr key={i}>
                     <td style={{ padding: '16px', fontWeight: '700', color: 'var(--text-muted)' }}>{row.label}</td>
                     <td style={{ padding: '16px', textAlign: 'right', fontWeight: '800', color: 'var(--accent-cyan)' }}>{row.value}</td>
                     <td style={{ padding: '16px', textAlign: 'center' }}>
                        <span className="live-badge" style={{ background: 'rgba(5, 150, 105, 0.1)', color: 'var(--accent-green)', padding: '4px 8px', fontSize: '9px' }}>NOMINAL</span>
                     </td>
                   </tr>
                 ))}
               </tbody>
             </table>
           </div>
        </div>

        {/* 2. Alert Logs (Detailed Table) */}
        <div className="dash-card">
           <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <div style={{ width: '4px', height: '16px', background: 'var(--accent-red)', borderRadius: '4px' }}></div>
              <h3 className="section-title" style={{ margin: 0 }}>Incident Response Logs (Critical)</h3>
           </div>
           <div className="table-container">
             <table className="premium-table">
               <thead>
                 <tr>
                   <th style={{ textAlign: 'left', padding: '12px 16px' }}>Attack Vector</th>
                   <th style={{ textAlign: 'left', padding: '12px 16px' }}>Source IP</th>
                   <th style={{ textAlign: 'left', padding: '12px 16px' }}>Target Node</th>
                   <th style={{ textAlign: 'right', padding: '12px 16px' }}>Protocol</th>
                   <th style={{ textAlign: 'right', padding: '12px 16px' }}>Timestamp</th>
                 </tr>
               </thead>
               <tbody>
                 {data?.alert_logs?.length > 0 ? data.alert_logs.map((log, i) => (
                   <tr key={i}>
                     <td style={{ padding: '16px' }}>
                        <span style={{ fontWeight: '800', color: 'var(--accent-red)', fontSize: '11px', padding: '4px 8px', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '4px' }}>
                          {log.Attack_Type}
                        </span>
                     </td>
                     <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-primary)', fontFamily: 'monospace' }}>{log.Source_IP}</td>
                     <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{log.Dest_IP || 'INTERNAL-SRS'}</td>
                     <td style={{ padding: '16px', textAlign: 'right', fontSize: '11px', fontWeight: '700' }}>{log.Protocol || 'TCP'}</td>
                     <td style={{ padding: '16px', textAlign: 'right', fontSize: '11px', color: 'var(--text-muted)' }}>{log.Timestamp?.split(' ')[1] || 'RECENT'}</td>
                   </tr>
                 )) : (
                   <tr>
                     <td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>NO CRITICAL INCIDENTS DETECTED</td>
                   </tr>
                 )}
               </tbody>
             </table>
           </div>
        </div>

        {/* 3. Blocked IP Table (Active Containments) */}
        <div className="dash-card">
           <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <div style={{ width: '4px', height: '16px', background: 'var(--accent-orange)', borderRadius: '4px' }}></div>
              <h3 className="section-title" style={{ margin: 0 }}>Active Threat Containment</h3>
           </div>
           <div className="table-container">
             <table className="premium-table">
               <thead>
                 <tr>
                   <th style={{ textAlign: 'left', padding: '12px 16px' }}>Blocked Source IP</th>
                   <th style={{ textAlign: 'center', padding: '12px 16px' }}>Attempt Count</th>
                   <th style={{ textAlign: 'right', padding: '12px 16px' }}>Last Violation</th>
                   <th style={{ textAlign: 'right', padding: '12px 16px' }}>Protection Status</th>
                 </tr>
               </thead>
               <tbody>
                 {data?.blocked_ips?.length > 0 ? data.blocked_ips.map((ip, i) => (
                   <tr key={i}>
                     <td style={{ padding: '16px', fontWeight: '800', color: 'var(--text-primary)', fontFamily: 'monospace' }}>{ip._id}</td>
                     <td style={{ padding: '16px', textAlign: 'center' }}>
                        <span style={{ fontSize: '10px', color: 'var(--accent-orange)', fontWeight: '900', padding: '2px 8px', border: '1px solid var(--accent-orange)', borderRadius: '12px' }}>
                          {ip.count} ATTEMPTS
                        </span>
                     </td>
                     <td style={{ padding: '16px', textAlign: 'right', fontSize: '11px', color: 'var(--text-muted)' }}>{ip.last_seen?.split(' ')[1] || 'STATIONARY'}</td>
                     <td style={{ padding: '16px', textAlign: 'right' }}>
                        <span style={{ fontSize: '10px', fontWeight: '800', color: 'var(--accent-red)' }}>BLOCKED</span>
                     </td>
                   </tr>
                 )) : (
                   <tr>
                     <td colSpan="4" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>ZERO ACTIVE THREAT CONTAINMENTS</td>
                   </tr>
                 )}
               </tbody>
             </table>
           </div>
        </div>
      </div>
    </div>
  )
}

