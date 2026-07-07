import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { fetchAPI, getAttackColor } from '../utils/IDS_API'
import { 
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, Legend
} from 'recharts'

function TopologyMap({ threatPercentage, hasThreat }) {
  const isDanger = threatPercentage > 30 || hasThreat;
  
  return (
    <div style={{ 
      padding: '24px', 
      background: 'rgba(255, 255, 255, 0.01)', 
      borderRadius: '12px', 
      border: '1px solid var(--border-color)', 
      marginBottom: '24px',
      boxShadow: 'inset 0 0 20px rgba(0,0,0,0.2)'
    }}>
      <svg viewBox="0 0 800 180" width="100%" height="100%" style={{ display: 'block', overflow: 'visible' }}>
        <defs>
          <filter id="neon-glow-blue" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <filter id="neon-glow-red" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* --- Path Connections --- */}
        {/* Gateway -> AI Engine */}
        <path d="M 100 80 L 300 80" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="6" opacity="0.1" strokeLinecap="round" />
        <path d="M 100 80 L 300 80" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-cyan)'} strokeWidth="2" strokeDasharray="8 12" strokeLinecap="round" className="laser-line" style={{ animationDuration: isDanger ? '0.6s' : '1.5s' }} />

        {/* AI Engine -> Firewall */}
        <path d="M 300 80 L 500 80" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="6" opacity="0.1" strokeLinecap="round" />
        <path d="M 300 80 L 500 80" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-cyan)'} strokeWidth="2" strokeDasharray="8 12" strokeLinecap="round" className="laser-line" style={{ animationDuration: isDanger ? '0.6s' : '1.5s' }} />

        {/* Firewall -> Clients */}
        <path d="M 500 80 L 700 80" stroke="var(--accent-green)" strokeWidth="6" opacity="0.1" strokeLinecap="round" />
        <path d="M 500 80 L 700 80" stroke="var(--accent-green)" strokeWidth="2" strokeDasharray="8 12" strokeLinecap="round" className="laser-line" style={{ animationDuration: '2s' }} />

        {/* --- Gateway Node --- */}
        <g transform="translate(100, 80)">
          <circle r="26" fill="var(--bg-dark)" stroke="var(--border-color)" strokeWidth="2" />
          <circle r="20" fill="rgba(99, 102, 241, 0.05)" stroke="var(--accent-blue)" strokeWidth="1" />
          <text y="6" fontSize="22" textAnchor="middle">🌐</text>
          <text y="50" fontSize="10" fontWeight="900" fill="var(--text-muted)" textAnchor="middle" letterSpacing="1px">EXTERNAL WAN</text>
          <text y="64" fontSize="8" fontWeight="800" fill="var(--accent-cyan)" textAnchor="middle" letterSpacing="0.5px">ACTIVE</text>
        </g>

        {/* --- AI Engine Node --- */}
        <g transform="translate(300, 80)">
          <circle r="28" fill="var(--bg-dark)" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="2" style={{ filter: isDanger ? 'url(#neon-glow-red)' : 'none', transition: 'all 0.3s' }} />
          <circle r="22" fill={isDanger ? 'var(--accent-red-soft)' : 'rgba(99, 102, 241, 0.05)'} stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="1" />
          <text y="7" fontSize="24" textAnchor="middle" className={isDanger ? 'pulse-heavy' : ''}>🧠</text>
          <text y="50" fontSize="10" fontWeight="900" fill="var(--text-muted)" textAnchor="middle" letterSpacing="1px">AI-IDS ENGINE</text>
          <text y="64" fontSize="8" fontWeight="800" fill={isDanger ? 'var(--accent-red)' : 'var(--accent-green)'} textAnchor="middle" letterSpacing="0.5px">{isDanger ? 'THREAT INBOUND' : 'EVALUATING'}</text>
        </g>

        {/* --- Firewall Node --- */}
        <g transform="translate(500, 80)">
          <circle r="28" fill="var(--bg-dark)" stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="2" style={{ filter: isDanger ? 'url(#neon-glow-red)' : 'none', transition: 'all 0.3s' }} />
          <circle r="22" fill={isDanger ? 'var(--accent-red-soft)' : 'rgba(99, 102, 241, 0.05)'} stroke={isDanger ? 'var(--accent-red)' : 'var(--accent-blue)'} strokeWidth="1" />
          <text y="6" fontSize="24" textAnchor="middle" className={isDanger ? 'pulse-heavy' : ''}>🛡️</text>
          <text y="50" fontSize="10" fontWeight="900" fill="var(--text-muted)" textAnchor="middle" letterSpacing="1px">FIREWALL</text>
          <text y="64" fontSize="8" fontWeight="800" fill={isDanger ? 'var(--accent-red)' : 'var(--accent-green)'} textAnchor="middle" letterSpacing="0.5px">{isDanger ? 'FILTERING ACTIVE' : 'SHIELDED'}</text>
        </g>

        {/* --- Clients Node --- */}
        <g transform="translate(700, 80)">
          <circle r="26" fill="var(--bg-dark)" stroke="var(--accent-green)" strokeWidth="2" />
          <circle r="20" fill="rgba(16, 185, 129, 0.05)" stroke="var(--accent-green)" strokeWidth="1" />
          <text y="6" fontSize="22" textAnchor="middle">💻</text>
          <text y="50" fontSize="10" fontWeight="900" fill="var(--text-muted)" textAnchor="middle" letterSpacing="1px">SECURE LAN</text>
          <text y="64" fontSize="8" fontWeight="800" fill="var(--accent-green)" textAnchor="middle" letterSpacing="0.5px">PROTECTED</text>
        </g>
      </svg>
    </div>
  );
}

export default function Overview() {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [attackTypes, setAttackTypes] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function loadData() {
    try {
      const [result, attackData] = await Promise.all([
        fetchAPI('/overview'),
        fetchAPI('/attack-types')
      ])
      setData(result)
      setAttackTypes(attackData.attack_types || [])
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

  const threatPercentage = parseFloat((data?.threat_percentage || 0).toFixed(1))

  let lastMinute = null;
  const processedChartData = data?.chart_data?.map(d => {
    const currentMinute = d?.time?.substring(0, 5); // Extract HH:MM
    if (currentMinute && currentMinute !== lastMinute) {
      lastMinute = currentMinute;
      return { ...d, displayTime: currentMinute };
    }
    return { ...d, displayTime: '' };
  }) || [];

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

      {/* 1. Attack Types Summary Grid */}
      {attackTypes.length > 0 && (
        <div className="attack-type-grid">
          {attackTypes.slice(0, 8).map((t, i) => {
            const theme = getAttackColor(t.attack_type);
            return (
              <div 
                key={i} 
                className="dash-card dash-card-mesh animate-stagger hover-glow" 
                style={{ borderLeft: `5px solid ${theme.color}`, padding: '24px', cursor: 'pointer', '--i': i }}
                onClick={() => navigate(`/attack-types/${t.attack_type}`)}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ fontSize: '10px', fontWeight: '900', color: 'var(--text-muted)', textTransform: 'uppercase', opacity: 0.8, letterSpacing: '1px' }}>{t.attack_type}</div>
                  <div style={{ fontSize: '38px', fontWeight: '900', color: 'var(--text-primary)', lineHeight: '1.1', letterSpacing: '-1px' }}>{t.count.toLocaleString()}</div>
                </div>
                
                <div style={{ marginTop: '24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', paddingTop: '16px', borderTop: '1px solid rgba(255,255,255,0.03)' }}>
                    <div>
                        <div style={{ fontSize: '8px', fontWeight: '900', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>AVERAGE RISK</div>
                        <div style={{ fontSize: '15px', fontWeight: '900', color: theme.color }}>{(t.avg_risk * 100).toFixed(1)}%</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '8px', fontWeight: '900', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>VECTORS</div>
                        <div style={{ fontSize: '15px', fontWeight: '900', color: 'var(--text-primary)' }}>{t.unique_ips}</div>
                    </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* 2. DYNAMIC INTEL GRID (Restructured) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', marginBottom: '24px' }}>
        
        {/* Top: Vector Graph */}
        <div className="dash-card dash-card-mesh animate-stagger" style={{ minHeight: '380px', '--i': 4 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 className="section-title" style={{ margin: 0 }}>Vectors</h3>
            <span style={{ fontSize: '9px', color: 'var(--accent-green)', fontWeight: '800' }}>IN/OUT</span>
          </div>
          <div style={{ height: '280px', width: '100%', position: 'relative' }}>
            {processedChartData.length > 0 ? (
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={processedChartData}>
                    <defs>
                      <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-green)" stopOpacity={0.25}/>
                        <stop offset="95%" stopColor="var(--accent-green)" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.25}/>
                        <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                    <XAxis 
                      dataKey="displayTime" 
                      stroke="var(--text-muted)" 
                      fontSize={10} 
                      tickLine={false} 
                      axisLine={false}
                      tickMargin={10}
                    />
                    <YAxis hide />
                    <Tooltip 
                      contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '12px', fontSize: '10px', backdropFilter: 'blur(10px)', color: 'var(--text-primary)' }}
                      labelFormatter={(label, payload) => payload?.[0]?.payload?.time || label}
                    />
                    <Area type="monotone" dataKey="incoming" stroke="var(--accent-green)" strokeWidth={2} fill="url(#colorIn)" name="Incoming" />
                    <Area type="monotone" dataKey="outgoing" stroke="var(--accent-blue)" strokeWidth={2} fill="url(#colorOut)" name="Outgoing" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="shimmer" style={{ width: '100%', height: '100%' }}></div>}
          </div>
        </div>

        {/* Bottom Split Row */}
        <div className="split-grid">
          
          {/* Bottom Left: Protocol Graph */}
          <div className="dash-card dash-card-mesh animate-stagger" style={{ minHeight: '380px', '--i': 5 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 className="section-title" style={{ margin: 0 }}>Protocols</h3>
              <span style={{ fontSize: '9px', color: 'var(--accent-blue)', fontWeight: '800' }}>TCP/UDP</span>
            </div>
            <div style={{ height: '280px', width: '100%', position: 'relative' }}>
              {processedChartData.length > 0 ? (
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={processedChartData}>
                      <defs>
                        <linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.25}/>
                          <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="colorUdp" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--accent-orange)" stopOpacity={0.25}/>
                          <stop offset="95%" stopColor="var(--accent-orange)" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis 
                        dataKey="displayTime" 
                        stroke="var(--text-muted)" 
                        fontSize={10} 
                        tickLine={false} 
                        axisLine={false}
                        tickMargin={10}
                      />
                      <YAxis hide />
                      <Tooltip 
                        contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '12px', fontSize: '10px', backdropFilter: 'blur(10px)', color: 'var(--text-primary)' }}
                        labelFormatter={(label, payload) => payload?.[0]?.payload?.time || label}
                      />
                      <Area type="monotone" dataKey="tcp" stroke="var(--accent-blue)" strokeWidth={2} fill="url(#colorTcp)" name="TCP" />
                      <Area type="monotone" dataKey="udp" stroke="var(--accent-orange)" strokeWidth={2} fill="url(#colorUdp)" name="UDP" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="shimmer" style={{ width: '100%', height: '100%' }}></div>}
            </div>
          </div>

          {/* Bottom Right: RISK METER */}
          <div className="dash-card animate-stagger" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', '--i': 6 }}>
              <h3 className="section-title" style={{ marginBottom: '16px' }}>Threat Index</h3>
              <div className="risk-meter-container">
                  <div className="risk-circle" style={{ 
                      width: '160px', height: '160px', 
                      border: '8px solid var(--border-color)',
                      boxShadow: `0 0 30px ${threatPercentage > 70 ? 'rgba(239, 68, 68, 0.12)' : (threatPercentage > 30 ? 'rgba(245, 158, 11, 0.12)' : 'rgba(99, 102, 241, 0.12)')}`,
                      borderColor: threatPercentage > 70 ? 'var(--accent-red-soft)' : (threatPercentage > 30 ? 'var(--accent-orange-soft)' : 'var(--accent-blue-soft)'),
                  }}>
                      {/* Holographic Radar Sweep Overlay */}
                      <div className="radar-sweep" style={{
                        background: `conic-gradient(from 0deg, ${threatPercentage > 70 ? 'var(--accent-red)' : (threatPercentage > 30 ? 'var(--accent-orange)' : 'var(--accent-blue)')} 0deg, transparent 180deg, transparent 360deg)`
                      }}></div>

                      <div className="label" style={{ zIndex: 2 }}>Composite</div>
                      <div className="value" style={{ 
                          fontSize: '38px', 
                          color: threatPercentage > 70 ? 'var(--accent-red)' : (threatPercentage > 30 ? 'var(--accent-orange)' : 'var(--accent-blue)'),
                          zIndex: 2
                      }}>{threatPercentage}%</div>
                      <div style={{ 
                          fontSize: '9px', fontWeight: '900', marginTop: '5px', letterSpacing: '2px',
                          color: threatPercentage > 70 ? 'var(--accent-red)' : (threatPercentage > 30 ? 'var(--accent-orange)' : 'var(--accent-blue)'),
                          zIndex: 2
                      }}>
                          {threatPercentage > 70 ? 'EMERGENCY' : (threatPercentage > 30 ? 'ELEVATED' : 'SECURE')}
                      </div>
                  </div>
              </div>
          </div>

        </div>

      </div>

      {/* 4. PREMIUM TABLES SECTION (Stacked Vertically) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        
        {/* 1. Network Status (Report Table) */}
        <div className="dash-card animate-stagger" style={{ '--i': 7 }}>
           <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
              <div style={{ width: '4px', height: '16px', background: 'var(--accent-blue)', borderRadius: '4px' }}></div>
              <h3 className="section-title" style={{ margin: 0 }}>Network Infrastructure Report</h3>
           </div>
           
           <TopologyMap threatPercentage={threatPercentage} hasThreat={data?.alert_logs?.length > 0} />

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
        <div className="dash-card animate-stagger" style={{ '--i': 8 }}>
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
                     <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-primary)', fontWeight: '600' }}>{log.Source_IP}</td>
                     <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-muted)', fontWeight: '600' }}>{log.Dest_IP || 'INTERNAL-SRS'}</td>
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
        <div className="dash-card animate-stagger" style={{ '--i': 9 }}>
           <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
             <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '4px', height: '16px', background: 'var(--accent-orange)', borderRadius: '4px' }}></div>
                <h3 className="section-title" style={{ margin: 0 }}>Active Threat Containment</h3>
             </div>
             <Link to="/blocked-ips" style={{ fontSize: '10px', color: 'var(--accent-black)', textDecoration: 'none', fontWeight: '800', letterSpacing: '1px' }}>VIEW ALL &rarr;</Link>
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
                     <td style={{ padding: '16px', fontWeight: '800', color: 'var(--text-primary)' }}>{ip._id}</td>
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

