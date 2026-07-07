import { Routes, Route, Navigate } from 'react-router-dom'
import { useState } from 'react'
import Login from './pages/Login'
import Navbar from './components/Navbar'
import Overview from './pages/Overview'
import LiveLogs from './pages/LiveLogs'
import Reports from './pages/Reports'
import History from './pages/History'
import AlertLogs from './pages/AlertLogs'
import BlockedIPs from './pages/BlockedIPs'
import AttackTypes from './pages/AttackTypes'
import Profile from './pages/Profile'
import TerminalConsole from './components/TerminalConsole'

function App() {
  const [authToken, setAuthToken] = useState(localStorage.getItem('ids_auth_token'))

  return (
    <Routes>
      <Route 
        path="/login" 
        element={!authToken ? <Login setAuthToken={setAuthToken} /> : <Navigate to="/" />} 
      />
      <Route 
        path="/*" 
        element={
          authToken ? (
            <div className="app-container">
              <Navbar authToken={authToken} setAuthToken={setAuthToken} />
              <main className="content-wrapper">
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/live-logs" element={<LiveLogs />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/history" element={<History />} />
                  <Route path="/alert-logs" element={<AlertLogs />} />
                  <Route path="/blocked-ips" element={<BlockedIPs />} />
                  <Route path="/attack-types/:type?" element={<AttackTypes />} />
                  <Route path="/profile/u/:id" element={<Profile authToken={authToken} setAuthToken={setAuthToken} />} />
                </Routes>
              </main>

              <footer style={{ padding: '40px 0', borderTop: '1px solid rgba(255,255,255,0.05)', marginTop: '60px', textAlign: 'center' }}>
                  <p style={{ fontSize: '12px', color: '#64748b', letterSpacing: '1px', textTransform: 'uppercase' }}>
                    AI-IDS Security Engine | Multi-Vector Defense | v78.2
                  </p>
                  <p style={{ fontSize: '10px', color: '#445566', marginTop: '8px' }}>
                    © 2026 STEALTH SECURITY SYSTEMS
                  </p>
              </footer>
              <TerminalConsole />
            </div>
          ) : (
            <Navigate to="/login" />
          )
        } 
      />
    </Routes>
  )
}

export default App
