import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, lazy, Suspense } from 'react'
import Login from './pages/Login'
import Navbar from './components/Navbar'

// Lazy load all pages for performance (code splitting)
const Overview = lazy(() => import('./pages/Overview'))
const LiveLogs = lazy(() => import('./pages/LiveLogs'))
const Reports = lazy(() => import('./pages/Reports'))
const History = lazy(() => import('./pages/History'))
const AlertLogs = lazy(() => import('./pages/AlertLogs'))
const BlockedIPs = lazy(() => import('./pages/BlockedIPs'))
const AttackTypes = lazy(() => import('./pages/AttackTypes'))
const Profile = lazy(() => import('./pages/Profile'))
const PipelineDashboard = lazy(() => import('./pages/PipelineDashboard'))

function LoadingFallback() {
  return (
    <div className="loading-screen">
      <div className="loading-spinner"></div>
      <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', letterSpacing: '2px', textTransform: 'uppercase' }}>
        LOADING MODULE...
      </div>
    </div>
  )
}

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
                <Suspense fallback={<LoadingFallback />}>
                  <Routes>
                    <Route path="/" element={<Overview />} />
                    <Route path="/live-logs" element={<LiveLogs />} />
                    <Route path="/reports" element={<Reports />} />
                    <Route path="/history" element={<History />} />
                    <Route path="/alert-logs" element={<AlertLogs />} />
                    <Route path="/blocked-ips" element={<BlockedIPs />} />
                    <Route path="/attack-types/:type?" element={<AttackTypes />} />
                    <Route path="/pipeline" element={<PipelineDashboard />} />
                    <Route path="/profile/u/:id" element={<Profile authToken={authToken} setAuthToken={setAuthToken} />} />
                  </Routes>
                </Suspense>
              </main>

              <footer style={{ padding: '40px 0', borderTop: '1px solid rgba(255,255,255,0.05)', marginTop: '60px', textAlign: 'center' }}>
                  <p style={{ fontSize: '12px', color: '#64748b', letterSpacing: '1px', textTransform: 'uppercase' }}>
                    CyberMatrix Security Engine | Multi-Vector Defense | v78.2
                  </p>
                  <p style={{ fontSize: '10px', color: '#445566', marginTop: '8px' }}>
                    © 2026 CYBERMATRIX SYSTEMS
                  </p>
              </footer>
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
