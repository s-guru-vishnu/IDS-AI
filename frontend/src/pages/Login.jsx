import { useState } from 'react'
import { API_BASE } from '../utils/IDS_API'

const Icons = {
    Eye: () => (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
        </svg>
    ),
    EyeOff: () => (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 1.24-2.33M1 1L23 23"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
        </svg>
    ),
    Shield: () => (
        <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
        </svg>
    )
}

export default function Login({ setAuthToken }) {
  const [isRegister, setIsRegister] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  
  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    
    if (isRegister && password !== confirmPassword) {
      setError('Passwords do not match')
      setLoading(false)
      return
    }

    const endpoint = isRegister ? '/register' : '/login'
    
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            username, 
            password,
            fullName: isRegister ? fullName : undefined,
            email: isRegister ? email : undefined,
            phone: isRegister ? phone : undefined
        })
      })
      const data = await res.json()
      
      if (data.success) {
        setAuthToken(data.token)
        localStorage.setItem('ids_auth_token', data.token)
        if (data.preferences?.theme) {
          localStorage.setItem('theme', data.preferences.theme)
          document.body.setAttribute('data-theme', data.preferences.theme)
        }
      } else {
        setError(data.error || 'Authentication failed')
      }
    } catch (err) {
      setError('Network error: server unreachable')
    }
    setLoading(false)
  }

  // Underlined Input Style
  const inputStyle = {
    width: '100%',
    padding: '12px 0',
    background: 'transparent',
    border: 'none',
    borderBottom: '2px solid var(--border-color)',
    color: 'var(--text-primary)',
    outline: 'none',
    transition: 'border-color 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    fontSize: '15px',
    fontWeight: '500',
    fontFamily: '"Plus Jakarta Sans", sans-serif'
  };

  const labelStyle = {
    display: 'block',
    fontSize: '11px',
    fontWeight: '800',
    color: 'var(--text-muted)',
    marginTop: '20px',
    letterSpacing: '0.5px'
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-dark)', padding: '40px 20px' }}>
      <div className="dash-card animate-in shadow-premium" style={{ 
        maxWidth: '460px', 
        width: '100%', 
        padding: '56px 48px', 
        background: 'var(--bg-card)', 
        borderRadius: '32px',
        border: '1px solid rgba(255, 255, 255, 0.03)'
      }}>
        
        {/* Title Section */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{ color: 'var(--accent-red)', marginBottom: '16px', display: 'flex', justifyContent: 'center' }}>
            <Icons.Shield />
          </div>
          <h1 style={{ margin: 0, fontSize: '32px', fontWeight: 900, color: 'var(--text-primary)', letterSpacing: '-1px' }}>
            {isRegister ? 'Create Account' : 'Login Now'}
          </h1>
          <p style={{ margin: '12px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>
             {isRegister ? 'Initialize your tactical profile.' : 'Verify authorization for the tactical dashboard.'}
          </p>
        </div>
        
        <form onSubmit={handleSubmit}>
          {error && (
            <div className="animate-in" style={{ background: 'rgba(220, 38, 38, 0.08)', color: 'var(--accent-red)', padding: '12px', borderRadius: '8px', fontSize: '11px', marginBottom: '24px', border: '1px solid rgba(220, 38, 38, 0.2)', fontWeight: 700, textAlign: 'center' }}>
              {error}
            </div>
          )}
          
          {isRegister && (
            <>
              <div>
                <label style={labelStyle}>FULL NAME</label>
                <input 
                  type="text" 
                  placeholder="Enter your identification name"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required={isRegister}
                  style={inputStyle}
                  onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
                  onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                />
              </div>
              <div>
                <label style={labelStyle}>GMAIL ID</label>
                <input 
                  type="email" 
                  placeholder="name@gmail.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required={isRegister}
                  style={inputStyle}
                  onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
                  onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                />
              </div>
              <div>
                <label style={labelStyle}>PHONE NUMBER</label>
                <input 
                  type="tel" 
                  placeholder="+X XXX XXX XXXX"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  required={isRegister}
                  style={inputStyle}
                  onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
                  onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                />
              </div>
            </>
          )}

          <div>
            <label style={labelStyle}>{isRegister ? 'CHOOSE USERNAME' : 'ADMINISTRATOR IDENTITY'}</label>
            <input 
              type="text" 
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={inputStyle}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
            />
          </div>
          
          <div>
            <label style={labelStyle}>{isRegister ? 'CREATE SECURITY PASSPHRASE' : 'SECURITY PASSPHRASE'}</label>
            <div style={{ position: 'relative' }}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  style={inputStyle}
                  onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
                  onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
                />
                <button 
                   type="button"
                   onClick={() => setShowPassword(!showPassword)}
                   style={{ position: 'absolute', right: '0', bottom: '12px', background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)' }}
                >
                    {showPassword ? <Icons.EyeOff /> : <Icons.Eye />}
                </button>
            </div>
          </div>

          {isRegister && (
            <div>
              <label style={labelStyle}>CONFIRM PASSPHRASE</label>
              <input 
                type="password" 
                placeholder="Repeat password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required={isRegister}
                style={inputStyle}
                onFocus={(e) => e.target.style.borderColor = 'var(--accent-red)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
              />
            </div>
          )}
          
          <button 
            type="submit" 
            className="hover-glow"
            style={{ 
                width: '100%', padding: '16px', borderRadius: '40px', background: 'var(--accent-red)', color: 'white', fontWeight: 900, border: 'none', cursor: 'pointer', transition: 'all 0.3s', 
                opacity: loading ? 0.7 : 1, fontSize: '14px', letterSpacing: '1px', textTransform: 'uppercase', marginTop: '40px', boxShadow: '0 8px 32px rgba(220, 38, 38, 0.15)'
            }}
          >
            {loading ? 'SYNCHRONIZING...' : (isRegister ? 'Sign Up' : 'Login')}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '32px' }}>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '24px' }}>
                {isRegister ? 'Already possess active credentials?' : "No established defense profile?"}
            </p>
            <button 
                onClick={() => { setIsRegister(!isRegister); setError(''); }}
                className="hover-glow"
                style={{ 
                    width: '100%', padding: '16px', borderRadius: '40px', background: 'rgba(255,255,255,0.03)', color: 'var(--text-primary)', fontWeight: 900, border: '1px solid var(--border-color)', 
                    cursor: 'pointer', fontSize: '14px', letterSpacing: '1px', textTransform: 'uppercase'
                }}
            >
                {isRegister ? 'Login Instead' : 'Sign Up'}
            </button>
        </div>
      </div>
    </div>
  )
}
