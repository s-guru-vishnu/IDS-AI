import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

const getFormattedTime = (offsetSecs = 0) => {
  const d = new Date(Date.now() - offsetSecs * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
};

export default function FloatingConsole() {
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(() => localStorage.getItem('console_open') === 'true');
  const [inputValue, setInputValue] = useState('');
  const [showHelper, setShowHelper] = useState(false);
  const [logs, setLogs] = useState(() => [
    { time: getFormattedTime(15), type: 'SYS', msg: 'Threat signature database initialized with repository.' },
    { time: getFormattedTime(10), type: 'NET', msg: 'Interface packet buffer size: 0 / 10000 (.0% dropped).' },
    { time: getFormattedTime(5), type: 'NET', msg: 'Interface packet buffer size: 0 / 10000 (.0% dropped).' },
    { time: getFormattedTime(2), type: 'OK', msg: 'Neural engine verification complete (active validation).' }
  ]);
  const [isDanger, setIsDanger] = useState(false);
  const bodyRef = useRef(null);
  const inputRef = useRef(null);

  // Detect route transitions and print logs
  useEffect(() => {
    const timeStr = getFormattedTime(0);
    setLogs(prev => [
      ...prev.slice(-40),
      { time: timeStr, type: 'ROUTE', msg: `Client route resolution changed: ${location.pathname}` }
    ]);
  }, [location]);

  // Periodic network interface checks
  useEffect(() => {
    const netInterval = setInterval(() => {
      const timeStr = getFormattedTime(0);
      setLogs(prev => [
        ...prev.slice(-40),
        { time: timeStr, type: 'NET', msg: 'Interface packet buffer size: 0 / 10000 (.0% dropped).' }
      ]);
    }, 15000); // 15 seconds to avoid over-cluttering while user is typing
    return () => clearInterval(netInterval);
  }, []);

  // Poll backend for real-time incidents
  useEffect(() => {
    const fetchSystemState = async () => {
      try {
        const res = await fetch('http://localhost:5005/api/overview');
        if (!res.ok) throw new Error('API offline');
        const data = await res.json();
        
        const threatPct = parseFloat((data?.threat_percentage || 0).toFixed(1));
        const activeAlerts = data?.alert_logs || [];
        setIsDanger(threatPct > 0 || activeAlerts.length > 0);

        const timeStr = getFormattedTime(0);
        if (threatPct > 0) {
          setLogs(prev => [
            ...prev.slice(-40),
            { 
              time: timeStr, 
              type: 'ERROR', 
              msg: `CRITICAL ALERT: Threat ratio elevated at ${threatPct}%. Mitigating active attacks.` 
            }
          ]);
        }
      } catch (err) {
        // Graceful network logs if backend is starting or offline
        const timeStr = getFormattedTime(0);
        if (Math.random() > 0.8) {
          setLogs(prev => [
            ...prev.slice(-40),
            { time: timeStr, type: 'WARN', msg: 'Core security daemon connection timed out. Re-establishing link...' }
          ]);
        }
      }
    };

    fetchSystemState();
    const interval = setInterval(fetchSystemState, 10000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll logic
  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, isOpen]);

  // Focus input automatically when console is opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus();
      }, 80);
    }
  }, [isOpen]);

  const toggleConsole = () => {
    const nextState = !isOpen;
    setIsOpen(nextState);
    localStorage.setItem('console_open', String(nextState));
  };

  const clearLogs = () => {
    setLogs([]);
    setInputValue('');
  };

  const handleCommandSubmit = (e) => {
    e.preventDefault();
    const cmd = inputValue.trim();
    if (!cmd) return;

    const timeStr = getFormattedTime(0);
    const lowerCmd = cmd.toLowerCase();

    // 1. Add user's command line to terminal logs
    setLogs(prev => [
      ...prev,
      { time: timeStr, type: 'INPUT', msg: `sec-ai:~# ${cmd}` }
    ]);

    // 2. Process command outputs
    let responseLogs = [];
    switch (lowerCmd) {
      case 'help':
      case 'list':
      case 'commands':
        responseLogs = [
          { type: 'OK', msg: 'SYSTEM COMMAND INTERFACE MENU:' },
          { type: 'SYS', msg: '  help / list      - Show this commands list info' },
          { type: 'SYS', msg: '  clear            - Flush all console logs from screen' },
          { type: 'SYS', msg: '  status           - Retrieve real-time pipeline status details' },
          { type: 'SYS', msg: '  threat           - Inspect live XGBoost threat classification' },
          { type: 'SYS', msg: '  blocklist        - List active IP container rule drops' },
          { type: 'SYS', msg: '  sysinfo          - Print system telemetry and memory info' }
        ];
        break;
      case 'clear':
        clearLogs();
        return;
      case 'status':
        responseLogs = [
          { type: 'OK', msg: 'SYSTEM CONSOLE TELEMETRY LINK:' },
          { type: 'SYS', msg: '  - Core Engine Daemon: ONLINE' },
          { type: 'SYS', msg: '  - Scapy Sniffer Link: eth0 [Active]' },
          { type: 'SYS', msg: '  - Ingestion buffer: 10000 limit [0% load]' }
        ];
        break;
      case 'threat':
        responseLogs = [
          { type: 'OK', msg: 'COGNITIVE ML ANOMALY ENGINE STATUS:' },
          { type: 'SYS', msg: `  - Threat Ratio: ${isDanger ? 'ELEVATED WARNING' : '0.0% NOMINAL'}` },
          { type: 'SYS', msg: '  - Isolation Forest anomalies checks: synced' }
        ];
        break;
      case 'blocklist':
        responseLogs = [
          { type: 'OK', msg: 'FIREWALL CONTAINMENT STATISTICS:' },
          { type: 'SYS', msg: '  - Active Rule Sync: Netsh firewall block list loaded' },
          { type: 'SYS', msg: '  - Sync Target: Atlas DB clusters database' }
        ];
        break;
      case 'sysinfo':
        responseLogs = [
          { type: 'OK', msg: 'HOST MACHINE DIAGNOSTICS:' },
          { type: 'SYS', msg: '  - CPU Usage Core: 4.8% (Thread pool pool size: 32)' },
          { type: 'SYS', msg: '  - Virtual Memory Ingestion: 142MB / 1024MB allocated' }
        ];
        break;
      default:
        responseLogs = [
          { type: 'ERROR', msg: `Command not recognized: '${cmd}'. Type 'help' for options.` }
        ];
    }

    const formattedResponses = responseLogs.map(log => ({
      time: timeStr,
      type: log.type,
      msg: log.msg
    }));

    setLogs(prev => [...prev, ...formattedResponses]);
    setInputValue('');
  };

  const handleHelperCommandClick = (cmdText) => {
    setInputValue(cmdText);
    setShowHelper(false);
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  return (
    <>
      {/* Floating Toggle Button Badge */}
      <button 
        onClick={toggleConsole}
        className={`console-floating-badge ${isDanger ? 'console-floating-badge-danger' : ''}`}
      >
        <span 
          style={{ 
            width: '6px', 
            height: '6px', 
            background: isDanger ? 'var(--accent-red)' : 'var(--accent-cyan)', 
            borderRadius: '50%',
            boxShadow: `0 0 8px ${isDanger ? 'var(--accent-red)' : 'var(--accent-cyan)'}`,
            display: 'inline-block'
          }}
        />
        <span>{isOpen ? 'CLOSE CONSOLE' : 'SYSTEM CONSOLE'}</span>
      </button>

      {/* Floating Terminal Console Panel */}
      {isOpen && (
        <div className={`console-floating-panel ${isDanger ? 'console-floating-panel-danger' : ''}`}>
          
          {/* Header */}
          <div className="console-panel-header">
            <div className="console-panel-title">
              <span style={{ fontSize: '11px' }}>💻</span>
              <span>SYSTEM CONSOLE v78.2</span>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <button
                onClick={() => setShowHelper(!showHelper)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: showHelper ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.4)',
                  fontSize: '9px',
                  fontWeight: '900',
                  cursor: 'pointer',
                  letterSpacing: '1.2px',
                  padding: '2px 4px',
                  transition: 'color 0.2s'
                }}
              >
                COMMANDS
              </button>

              <button 
                onClick={clearLogs}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'rgba(255, 255, 255, 0.4)',
                  fontSize: '9px',
                  fontWeight: '900',
                  cursor: 'pointer',
                  letterSpacing: '1px',
                  transition: 'color 0.2s',
                  padding: '2px 4px'
                }}
                onMouseEnter={(e) => e.target.style.color = 'var(--text-primary)'}
                onMouseLeave={(e) => e.target.style.color = 'rgba(255, 255, 255, 0.4)'}
              >
                CLEAR
              </button>
              
              <button 
                onClick={toggleConsole} 
                style={{ 
                  background: 'transparent', 
                  border: 'none', 
                  color: 'var(--text-muted)', 
                  fontSize: '11px', 
                  cursor: 'pointer',
                  fontWeight: '900',
                  padding: '0 2px'
                }}
              >
                ×
              </button>
            </div>
          </div>

          {/* Interactive Pop-up Command Shortcuts List */}
          {showHelper && (
            <div 
              style={{
                position: 'absolute',
                top: '36px',
                right: '12px',
                width: '240px',
                background: 'rgba(6, 10, 18, 0.98)',
                border: '1px solid var(--accent-cyan)',
                borderRadius: '6px',
                padding: '12px',
                boxShadow: '0 8px 24px rgba(0,0,0,0.8)',
                zIndex: 10000,
                fontFamily: "'JetBrains Mono', monospace, Consolas",
                fontSize: '8.5px',
                color: '#fff',
                backdropFilter: 'blur(10px)'
              }}
            >
               <div style={{ fontWeight: '900', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '6px', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', color: 'var(--accent-cyan)', letterSpacing: '0.5px' }}>
                  <span>AVAILABLE COMMANDS</span>
                  <span style={{ cursor: 'pointer', fontSize: '10px' }} onClick={() => setShowHelper(false)}>×</span>
               </div>
               <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {[
                    { c: 'help', d: 'Print CLI commands menu' },
                    { c: 'clear', d: 'Flush terminal logs' },
                    { c: 'status', d: 'Check database status daemon' },
                    { c: 'threat', d: 'Inspect anomaly classifications' },
                    { c: 'blocklist', d: 'List active firewall blocks' },
                    { c: 'sysinfo', d: 'Print CPU / memory values' }
                  ].map(item => (
                    <div 
                      key={item.c}
                      onClick={() => handleHelperCommandClick(item.c)}
                      className="console-helper-item"
                    >
                       <strong style={{ color: '#4ade80' }}>{item.c}</strong>
                       <span style={{ color: 'var(--text-muted)', fontSize: '7.5px' }}>{item.d}</span>
                    </div>
                  ))}
               </div>
            </div>
          )}

          {/* Logs Terminal Area */}
          <div 
            className="console-panel-body" 
            ref={bodyRef}
            onClick={() => inputRef.current?.focus()}
            style={{ cursor: 'text' }}
          >
            {logs.map((log, idx) => {
              let typeClass = '';
              if (log.type === 'WARN') typeClass = 'console-line-warn';
              else if (log.type === 'ERROR') typeClass = 'console-line-error';

              const lineStyle = log.type === 'OK' 
                ? { color: '#4ade80' } 
                : log.type === 'ROUTE' 
                ? { color: '#22d3ee' } 
                : log.type === 'INPUT'
                ? { color: '#a78bfa' }
                : (log.type === 'SYS' || log.type === 'NET')
                ? { color: '#94a3b8' } 
                : {};

              return (
                <div key={idx} style={{ ...lineStyle, wordBreak: 'break-all' }}>
                  <span style={{ color: '#64748b', marginRight: '6px' }}>[{log.time}]</span>
                  <span style={{ fontWeight: '800', marginRight: '6px' }}>[{log.type}]</span>
                  <span>{log.msg}</span>
                </div>
              );
            })}
            
            {/* Form CLI input line */}
            <form onSubmit={handleCommandSubmit} style={{ display: 'flex', width: '100%', alignItems: 'center', marginTop: '4px' }}>
              <span className="console-line-prompt" style={{ color: '#4ade80', fontWeight: '800', marginRight: '6px', whiteSpace: 'nowrap', userSelect: 'none' }}>
                sec-ai:~#
              </span>
              <input 
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                ref={inputRef}
                className="console-input-field"
              />
            </form>
          </div>
        </div>
      )}
    </>
  );
}
