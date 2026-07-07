import { useState, useEffect } from 'react'
import { API_BASE } from '../utils/IDS_API'
import { useParams, useNavigate } from 'react-router-dom'

export default function Profile({ authToken, setAuthToken }) {
  const { id } = useParams()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('account')
  const [settings, setSettings] = useState(null)
  
  // Account Form
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [fullName, setFullName] = useState('')
  
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  const [loading, setLoading] = useState(false)
  const [msg, setMsg] = useState({ text: '', type: '' })

  // Engine Config
  const [autoBlock, setAutoBlock] = useState(true)
  const [criticalThreshold, setCriticalThreshold] = useState(90)
  const [highThreshold, setHighThreshold] = useState(70)

  useEffect(() => {
    if (authToken) {
      fetchSettings()
    }
  }, [authToken])

  const fetchSettings = async () => {
    try {
      const res = await fetch(`${API_BASE}/settings`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      const data = await res.json()
      if (data.success) {
        setSettings(data)
        setUsername(data.username)
        setEmail(data.email || '')
        setPhone(data.phone || '')
        setFullName(data.full_name || '')
        
        if (data.engine_config) {
          setAutoBlock(data.engine_config.auto_block_enabled)
          setCriticalThreshold(data.engine_config.critical_risk_threshold * 100)
          setHighThreshold(data.engine_config.high_risk_threshold * 100)
        }
        // Redirect if URL doesn't match
        if (id !== data.username) {
            navigate(`/profile/u/${data.username}`, { replace: true })
        }
      }
    } catch (err) {
      console.error('Failed to load settings')
    }
  }

  const handleSaveAccount = async (e) => {
    e.preventDefault()
    if (newPassword && newPassword !== confirmPassword) {
      setMsg({ text: 'New passwords do not match', type: 'error' })
      return
    }
    
    setLoading(true)
    setMsg({ text: '', type: '' })
    
    try {
      const payload = { 
        username,
        email,
        phone
      }
      if (newPassword) {
        payload.current_password = currentPassword
        payload.new_password = newPassword
      }
      
      const res = await fetch(`${API_BASE}/settings`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify(payload)
      })
      const data = await res.json()
      
      if (data.success) {
        setMsg({ text: 'Profile updated successfully', type: 'success' })
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
        setSettings({...settings, username, email, phone})
        if (username !== id) {
             navigate(`/profile/u/${username}`, { replace: true })
        }
      } else {
        setMsg({ text: data.error || 'Update failed', type: 'error' })
      }
    } catch (err) {
      setMsg({ text: 'Network error', type: 'error' })
    }
    setLoading(false)
  }

  const handleSaveConfig = async (e) => {
    e.preventDefault()
    setLoading(true)
    setMsg({ text: '', type: '' })

    try {
      const payload = {
        engine_config: {
          auto_block_enabled: autoBlock,
          critical_risk_threshold: criticalThreshold / 100,
          high_risk_threshold: highThreshold / 100
        }
      }

      const res = await fetch(`${API_BASE}/settings`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify(payload)
      })
      const data = await res.json()
      
      if (data.success) {
        setMsg({ text: 'Engine configuration updated', type: 'success' })
      } else {
        setMsg({ text: data.error || 'Update failed', type: 'error' })
      }
    } catch (err) {
      setMsg({ text: 'Network error', type: 'error' })
    }
    setLoading(false)
  }

  const handleLogout = () => {
    localStorage.removeItem('ids_auth_token')
    setAuthToken(null)
    navigate('/')
  }

  return (
    <div className="animate-in" style={{ padding: '0 24px', maxWidth: '1200px', margin: '0 auto' }}>
      <div className="page-intro" style={{ marginBottom: '32px' }}>
        <div>
          <h2>User Profile</h2>
          <p>Manage authentication credentials and session details for {username || id}.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '250px 1fr', gap: '32px' }}>
        
        {/* Sidebar */}
        <div className="dash-card" style={{ padding: '20px' }}>
          <div style={{ textAlign: 'center', marginBottom: '32px' }}>
             <div style={{ 
                width: '80px', height: '80px', borderRadius: '50%', background: 'linear-gradient(135deg, var(--accent-blue), #2563eb)', 
                margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'white', fontSize: '32px', fontWeight: '800', boxShadow: '0 8px 24px rgba(37, 99, 235, 0.25)' 
             }}>
                 {(username || id || 'U').charAt(0).toUpperCase()}
             </div>
             <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>{username || 'Admin'}</h3>
             <span style={{ fontSize: '11px', color: 'var(--accent-blue)', fontWeight: '800' }}>SECURITY OPERATOR</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <button 
              onClick={() => setActiveTab('account')}
              style={{ width: '100%', textAlign: 'left', padding: '12px 16px', background: activeTab === 'account' ? 'var(--accent-red-soft)' : 'transparent', color: activeTab === 'account' ? 'var(--accent-red)' : 'var(--text-secondary)', border: 'none', borderRadius: '8px', fontSize: '12px', fontWeight: 800, cursor: 'pointer', transition: 'all 0.2s' }}
            >
              Account & Security
            </button>
            <button 
              onClick={() => setActiveTab('preferences')}
              style={{ width: '100%', textAlign: 'left', padding: '12px 16px', background: activeTab === 'preferences' ? 'rgba(255,255,255,0.05)' : 'transparent', color: activeTab === 'preferences' ? 'var(--text-primary)' : 'var(--text-secondary)', border: 'none', borderRadius: '8px', fontSize: '12px', fontWeight: 800, cursor: 'pointer', transition: 'all 0.2s' }}
            >
              Dashboard Config
            </button>
          </div>

          <div style={{ marginTop: '32px', paddingTop: '20px', borderTop: '1px solid var(--border-color)' }}>
            <button 
                onClick={handleLogout} 
                style={{ 
                    width: '100%', padding: '12px', background: 'transparent', border: '1px solid rgba(220,38,38,0.3)', 
                    color: 'var(--accent-red)', borderRadius: '8px', fontSize: '11px', fontWeight: 800, cursor: 'pointer',
                    transition: 'all 0.2s'
                }}
                onMouseOver={(e) => { e.target.style.background = 'var(--accent-red-soft)'; e.target.style.borderColor = 'var(--accent-red)' }}
                onMouseOut={(e) => { e.target.style.background = 'transparent'; e.target.style.borderColor = 'rgba(220,38,38,0.3)' }}
            >
              LOGOUT SYSTEM
            </button>
          </div>
        </div>

        {/* Content Area */}
        <div className="dash-card" style={{ padding: '40px' }}>
            {activeTab === 'account' && (
              <div style={{ maxWidth: '600px' }}>
                <h4 style={{ margin: '0 0 8px 0', fontSize: '20px', color: 'var(--text-primary)', fontWeight: 800 }}>Account Identity</h4>
                <p style={{ margin: '0 0 32px 0', fontSize: '12px', color: 'var(--text-secondary)' }}>Manage your administrative profile and tactical signatures.</p>
                
                {msg.text && (
                  <div style={{ padding: '12px 16px', borderRadius: '8px', fontSize: '12px', marginBottom: '24px', background: msg.type === 'error' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(16, 185, 129, 0.1)', color: msg.type === 'error' ? 'var(--accent-red)' : '#10b981', border: `1px solid ${msg.type === 'error' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(16, 185, 129, 0.2)'}` }}>
                    {msg.text}
                  </div>
                )}

                {/* Profile Information Display */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '40px', padding: '24px', background: 'rgba(255,255,255,0.02)', borderRadius: '16px', border: '1px solid var(--border-color)' }}>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--accent-blue)', marginBottom: '4px' }}>FULL IDENTIFICATION</label>
                        <div style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 600 }}>{settings?.full_name || 'Not Registered'}</div>
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--accent-blue)', marginBottom: '4px' }}>GMAIL ADDRESS</label>
                        <div style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 600 }}>{settings?.email || 'Not Registered'}</div>
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--accent-blue)', marginBottom: '4px' }}>PHONE CONTACT</label>
                        <div style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 600 }}>{settings?.phone || 'Not Registered'}</div>
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--accent-blue)', marginBottom: '4px' }}>ADMIN ID</label>
                        <div style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 600 }}>{username}</div>
                    </div>
                </div>

                <div style={{ marginBottom: '40px', padding: '24px', background: 'rgba(220,38,38,0.05)', borderRadius: '16px', border: '1px solid rgba(220,38,38,0.2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                        <div style={{ padding: '8px', background: 'var(--accent-red)', borderRadius: '8px', color: 'white' }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                        </div>
                        <h5 style={{ margin: 0, fontSize: '14px', fontWeight: 900, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '1px' }}>Tactical Node Signatures</h5>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                        <div>
                            <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-muted)', marginBottom: '4px' }}>CLIENT HOST IP</label>
                            <code style={{ fontSize: '13px', color: 'var(--accent-red)', fontWeight: 800 }}>{settings?.ip_address || '127.0.0.1'}</code>
                        </div>
                        <div>
                            <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-muted)', marginBottom: '4px' }}>MAC SIGNATURE</label>
                            <code style={{ fontSize: '13px', color: 'var(--accent-red)', fontWeight: 800 }}>{settings?.mac_address || '00:00:00:00:00:00'}</code>
                        </div>
                    </div>
                </div>

                <h5 style={{ margin: '0 0 20px 0', fontSize: '14px', color: 'var(--text-primary)', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px' }}>Update Profile Signatures</h5>
                
                <form onSubmit={handleSaveAccount}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '24px' }}>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>ADMIN USERNAME</label>
                        <input type="text" value={username} onChange={e => setUsername(e.target.value)} required style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>FULL NAME (READ ONLY)</label>
                        <input type="text" value={fullName} readOnly style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.02)', color: 'var(--text-muted)', outline: 'none', fontSize: '13px', cursor: 'not-allowed' }} />
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '32px' }}>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>GMAIL ADDRESS</label>
                        <input type="email" value={email} onChange={e => setEmail(e.target.value)} required style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                    </div>
                    <div>
                        <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>PHONE CONTACT</label>
                        <input type="tel" value={phone} onChange={e => setPhone(e.target.value)} required style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                    </div>
                  </div>

                  <h5 style={{ margin: '32px 0 20px 0', fontSize: '14px', color: 'var(--text-primary)', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', borderTop: '1px solid var(--border-color)', paddingTop: '24px' }}>Security Secrets</h5>
                  
                  <div style={{ marginBottom: '24px' }}>
                    <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>CURRENT PASSWORD <span style={{ opacity: 0.6 }}>(Required to change password)</span></label>
                    <input type="password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} placeholder="Leave blank to keep current" style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                  </div>
                  
                  <div style={{ display: 'flex', gap: '16px', marginBottom: '32px' }}>
                    <div style={{ flex: 1 }}>
                      <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>NEW PASSWORD</label>
                      <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label style={{ display: 'block', fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)', marginBottom: '8px' }}>CONFIRM REPEAT</label>
                      <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} style={{ width: '100%', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-card)', color: 'var(--text-primary)', outline: 'none', fontSize: '13px' }} />
                    </div>
                  </div>

                  <button 
                    type="submit" 
                    disabled={loading} 
                    className="hover-glow interactive-card"
                    style={{ padding: '12px 32px', borderRadius: '8px', background: 'var(--accent-red)', color: 'white', fontWeight: 800, border: 'none', cursor: 'pointer', fontSize: '12px', transition: 'all 0.2s', opacity: loading ? 0.7 : 1 }}
                  >
                    {loading ? 'SAVING...' : 'UPDATE SECRETS'}
                  </button>
                </form>
              </div>
            )}

            {activeTab === 'preferences' && (
              <div style={{ maxWidth: '480px' }}>
                <h4 style={{ margin: '0 0 8px 0', fontSize: '20px', color: 'var(--text-primary)', fontWeight: 800 }}>Dashboard Configuration</h4>
                <p style={{ margin: '0 0 32px 0', fontSize: '12px', color: 'var(--text-secondary)' }}>Configure active defense and AI engine behavior.</p>
                
                {msg.text && (
                  <div style={{ padding: '12px 16px', borderRadius: '8px', fontSize: '12px', marginBottom: '24px', background: msg.type === 'error' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(16, 185, 129, 0.1)', color: msg.type === 'error' ? 'var(--accent-red)' : '#10b981', border: `1px solid ${msg.type === 'error' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(16, 185, 129, 0.2)'}` }}>
                    {msg.text}
                  </div>
                )}

                <form onSubmit={handleSaveConfig}>
                  <div style={{ marginBottom: '32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: '800', color: 'var(--text-primary)' }}>AUTO-BLOCK ENGINE</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Automatically blacklist high-risk entities.</div>
                    </div>
                    <label className="switch" style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
                      <input type="checkbox" checked={autoBlock} onChange={e => setAutoBlock(e.target.checked)} style={{ opacity: 0, width: 0, height: 0 }} />
                      <span style={{ position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: autoBlock ? 'var(--accent-red)' : '#ccc', transition: '.4s', borderRadius: '34px' }}>
                        <span style={{ position: 'absolute', content: '""', height: '18px', width: '18px', left: autoBlock ? '22px' : '4px', bottom: '3px', backgroundColor: 'white', transition: '.4s', borderRadius: '50%' }}></span>
                      </span>
                    </label>
                  </div>

                  <div style={{ marginBottom: '24px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                      <label style={{ fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)' }}>CRITICAL RISK THRESHOLD</label>
                      <span style={{ fontSize: '12px', fontWeight: '900', color: 'var(--accent-red)' }}>{criticalThreshold}%</span>
                    </div>
                    <input type="range" min="0" max="100" value={criticalThreshold} onChange={e => setCriticalThreshold(e.target.value)} style={{ width: '100%', accentColor: 'var(--accent-red)' }} />
                  </div>

                  <div style={{ marginBottom: '32px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
                      <label style={{ fontSize: '10px', fontWeight: 800, color: 'var(--text-secondary)' }}>HIGH RISK ALERT THRESHOLD</label>
                      <span style={{ fontSize: '12px', fontWeight: '900', color: 'var(--accent-orange)' }}>{highThreshold}%</span>
                    </div>
                    <input type="range" min="0" max="100" value={highThreshold} onChange={e => setHighThreshold(e.target.value)} style={{ width: '100%', accentColor: 'var(--accent-orange)' }} />
                  </div>

                  <button 
                    type="submit" 
                    disabled={loading} 
                    className="hover-glow interactive-card"
                    style={{ padding: '12px 32px', borderRadius: '8px', background: 'var(--accent-red)', color: 'white', fontWeight: 800, border: 'none', cursor: 'pointer', fontSize: '12px', transition: 'all 0.2s', opacity: loading ? 0.7 : 1 }}
                  >
                    {loading ? 'SAVING...' : 'APPLY CONFIGURATION'}
                  </button>
                </form>
              </div>
            )}
        </div>
      </div>
    </div>
  )
}
