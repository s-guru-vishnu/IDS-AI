import { useState, useEffect } from 'react'
import { fetchAPI, getAttackColor } from '../utils/IDS_API'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, Cell, PieChart, Pie
} from 'recharts'

export default function PipelineDashboard() {
  const [stats, setStats] = useState(null)
  const [bufferStats, setBufferStats] = useState(null)
  const [zeroDayAlerts, setZeroDayAlerts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function loadData() {
    try {
      const [pipelineRes, bufferRes, zeroDayRes] = await Promise.all([
        fetchAPI('/pipeline-stats'),
        fetchAPI('/flow-buffer-stats'),
        fetchAPI('/zero-day-alerts?limit=5')
      ])
      setStats(pipelineRes)
      setBufferStats(bufferRes)
      setZeroDayAlerts(zeroDayRes.zero_day_alerts || [])
    } catch (err) {
      console.error('Failed to load pipeline stats:', err)
    } finally {
      setLoading(false)
    }
  }

  if (loading && !stats) return (
    <div style={{ display: 'flex', height: '60vh', alignItems: 'center', justifyContent: 'center' }}>
      <div className="status-pulse" style={{ width: '40px', height: '40px', background: 'var(--accent-blue)' }}></div>
    </div>
  )

  // Prepare timing data for chart
  const timingData = stats?.timing ? [
    { name: 'L1: Capture', value: stats.timing.avg_capture, color: '#6366f1' },
    { name: 'L2: Feature', value: stats.timing.avg_feature, color: '#818cf8' },
    { name: 'L3: Behavioral', value: stats.timing.avg_behavior, color: '#a78bfa' },
    { name: 'L4: ML', value: stats.timing.avg_ml, color: '#c084fc' },
    { name: 'L5: AI Defense', value: stats.timing.avg_ai_defense, color: '#f472b6' },
    { name: 'L6: Intel', value: stats.timing.avg_intelligence, color: '#fb7185' },
    { name: 'L7: Correlation', value: stats.timing.avg_correlation, color: '#fb923c' },
    { name: 'L8: Zero-Day', value: stats.timing.avg_zero_day, color: '#fbbf24' },
    { name: 'L9: Decision', value: stats.timing.avg_decision, color: '#4ade80' },
    { name: 'L10: Response', value: stats.timing.avg_response, color: '#2dd4bf' },
  ].filter(d => d.value > 0) : []

  const totalResponseTime = stats?.timing?.avg_total_response || 0

  return (
    <div className="animate-in" style={{ paddingBottom: '60px' }}>
      <div className="page-intro">
        <div>
          <h2>10-Layer Flow Defense</h2>
          <p>Real-time telemetry from the Cyber Defense AI pipeline.</p>
        </div>
        <div style={{ textAlign: 'right' }}>
           <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: '800', letterSpacing: '1px' }}>AVG DETECTION</div>
           <div style={{ fontSize: '24px', fontWeight: '900', color: 'var(--accent-blue)' }}>{totalResponseTime.toFixed(3)}<span style={{ fontSize: '12px', opacity: 0.5 }}> MS</span></div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '24px', marginBottom: '24px' }}>
        
        {/* 1. LAYERED LATENCY ANALYTICS */}
        <div className="dash-card">
          <h3 className="section-title">Latency Breakdown (ms)</h3>
          <div style={{ height: '400px', width: '100%', marginTop: '20px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timingData} layout="vertical" margin={{ left: 40, right: 30 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" width={100} style={{ fontSize: '10px', fontWeight: '700' }} />
                <Tooltip 
                  cursor={{ fill: 'transparent' }}
                  contentStyle={{ background: 'var(--bg-card)', border: 'none', borderRadius: '8px', fontSize: '11px', boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)' }}
                  formatter={(value) => [`${value.toFixed(4)} ms`, 'Latency']}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
                  {timingData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 2. FLOW BUFFER TELEMETRY */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="dash-card dash-card-mesh">
                <h3 className="section-title">Flow Buffer Metrics</h3>
                <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div>
                        <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: '800' }}>AVG PACKET CT</div>
                        <div style={{ fontSize: '20px', fontWeight: '800' }}>{Math.round(bufferStats?.buffer_stats?.avg_packet_count || 0)}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: '800' }}>AVG DURATION</div>
                        <div style={{ fontSize: '20px', fontWeight: '800' }}>{bufferStats?.buffer_stats?.avg_duration?.toFixed(1) || 0}s</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: '800' }}>AVG ENTROPY</div>
                        <div style={{ fontSize: '20px', fontWeight: '800', color: 'var(--accent-purple)' }}>{bufferStats?.buffer_stats?.avg_entropy?.toFixed(3) || 0}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: '800' }}>ZERO-DAYS</div>
                        <div style={{ fontSize: '20px', fontWeight: '800', color: 'var(--accent-orange)' }}>{stats?.zero_day_count || 0}</div>
                    </div>
                </div>
                <div style={{ marginTop: '20px', padding: '16px', background: 'var(--bg-surface)', borderRadius: '12px' }}>
                     <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                        <span style={{ fontSize: '10px', fontWeight: '700' }}>Optimization Load</span>
                        <span style={{ fontSize: '10px', fontWeight: '700', color: 'var(--accent-green)' }}>{(stats?.timing?.avg_total_response < 0.35 ? 'HEALTHY' : 'LOADED')}</span>
                     </div>
                     <div style={{ height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px' }}>
                        <div style={{ 
                            height: '100%', 
                            width: `${Math.min(100, (stats?.timing?.avg_total_response / 0.5) * 100)}%`, 
                            background: stats?.timing?.avg_total_response < 0.35 ? 'var(--accent-green)' : 'var(--accent-red)',
                            borderRadius: '2px'
                        }}></div>
                     </div>
                </div>
            </div>

            <div className="dash-card">
                <h3 className="section-title">Optimization Usage</h3>
                <div style={{ marginTop: '10px' }}>
                    {Object.entries(bufferStats?.optimization_usage || {}).map(([key, val], i) => (
                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-color)' }}>
                            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{key.replace(/_/g, ' ')}</span>
                            <span style={{ fontSize: '11px', fontWeight: '800' }}>{val}</span>
                        </div>
                    ))}
                    {Object.keys(bufferStats?.optimization_usage || {}).length === 0 && (
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', padding: '20px 0', textAlign: 'center' }}>No optimizations active</div>
                    )}
                </div>
            </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '24px' }}>
        
        {/* 3. ZERO-DAY ALERT FEED */}
        <div className="dash-card" style={{ borderLeft: '4px solid var(--accent-orange)' }}>
            <h3 className="section-title">Zero-Day / Novel Patterns</h3>
            <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {zeroDayAlerts.length > 0 ? zeroDayAlerts.map((alert, i) => (
                    <div key={i} style={{ padding: '12px', background: 'rgba(251, 191, 36, 0.05)', borderRadius: '8px', border: '1px solid rgba(251, 191, 36, 0.1)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                            <span style={{ fontSize: '10px', fontWeight: '900', color: 'var(--accent-orange)' }}>PATTERN {alert.pattern_id}</span>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{alert.Timestamp?.split(' ')[1]}</span>
                        </div>
                        <div style={{ fontSize: '12px', fontWeight: '700', marginBottom: '6px' }}>{alert.src_ip} -&gt; {alert.dst_ip}</div>
                        <div style={{ fontSize: '10px', opacity: 0.7, color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                            {alert.reason?.substring(0, 80)}...
                        </div>
                        <div style={{ marginTop: '8px', display: 'flex', gap: '8px' }}>
                            <span style={{ fontSize: '9px', padding: '2px 6px', background: 'var(--accent-orange)', color: 'white', borderRadius: '4px', fontWeight: '800' }}>ANOMALY: {alert.anomaly_score?.toFixed(2)}</span>
                            <span style={{ fontSize: '9px', padding: '2px 6px', background: 'rgba(0,0,0,0.2)', color: 'var(--text-muted)', borderRadius: '4px' }}>CONF: {alert.confidence?.toFixed(2)}</span>
                        </div>
                    </div>
                )) : (
                    <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)', fontSize: '12px' }}>
                        No novel patterns detected.
                    </div>
                )}
            </div>
        </div>

        {/* 4. RECENT PIPELINE RESULTS */}
        <div className="dash-card">
            <h3 className="section-title">Execution History</h3>
            <div className="table-container" style={{ marginTop: '20px' }}>
                <table className="premium-table">
                    <thead>
                        <tr>
                            <th>Flow ID</th>
                            <th>Attack Type</th>
                            <th>Action</th>
                            <th style={{ textAlign: 'right' }}>Latency</th>
                        </tr>
                    </thead>
                    <tbody>
                        {stats?.total_pipeline_results > 0 ? (
                            <tr style={{ background: 'transparent' }}><td colSpan="4" style={{ padding: '0' }} /></tr>
                        ) : null}
                    </tbody>
                </table>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', textAlign: 'center', padding: '40px' }}>
                    View full execution history in the <b>Live Logs</b> tab.
                </div>
            </div>
        </div>
      </div>
    </div>
  )
}
