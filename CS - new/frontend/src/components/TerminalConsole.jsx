import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

const TELEMETRY_POOL = [
  '[SYS] Core memory utilization: 42.8% | CPU temperature: 48.5°C',
  '[SYS] Threat Signature Database synchronized with repository.',
  '[SYS] Optimizing neural network classifier weight matrices...',
  '[OK] Neural engine verification complete (fp16 validation).',
  '[NET] Interface packet buffer size: 0 / 15000 (0.0% dropped).',
  '[OK] TCP SYN-flood firewall mitigation rules loaded.',
  '[NET] Capture driver listening on primary interface (Npcap driver).',
  '[OK] Explainable AI engine API handshakes: STABLE',
  '[SYS] Executing scheduled telemetry integrity sweep... [OK]',
  '[SYS] Secure tunnel connection established with main cluster.',
  '[OK] Active iptables rules refreshed. 0 leakage detected.'
];

export default function TerminalConsole() {
  const [isOpen, setIsOpen] = useState(false);
  const [inputValue, setInputValue] = useState('');
  const [logs, setLogs] = useState([
    '[BOOT] Stealth Security AI-IDS v78.2 initializing...',
    '[BOOT] Mapping strategic memory blocks...',
    '[BOOT] Connecting to local capture driver...',
    '[OK] Connection established on port 5005.',
    '[SYS] Neural classification models: ACTIVE.',
    '[SYS] Firewall rules sync complete. Shielding protected LAN.'
  ]);
  
  const location = useLocation();
  const logEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto scroll to bottom of console logs
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isOpen]);

  // Focus input when terminal opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Log navigation events
  useEffect(() => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [
      ...prev, 
      `[${timestamp}] [ROUTE] Client route resolution changed: ${location.pathname}`
    ].slice(-40));
  }, [location]);

  // Simulated background telemetry logs loop
  useEffect(() => {
    const interval = setInterval(() => {
      const timestamp = new Date().toLocaleTimeString();
      const randomLog = TELEMETRY_POOL[Math.floor(Math.random() * TELEMETRY_POOL.length)];
      setLogs(prev => [...prev, `[${timestamp}] ${randomLog}`].slice(-40));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const clearConsole = (e) => {
    if (e) e.stopPropagation();
    setLogs([`[${new Date().toLocaleTimeString()}] [SYS] Console logs cleared by security admin.`]);
  };

  const handleCommandSubmit = (e) => {
    e.preventDefault();
    const cmdText = inputValue.trim();
    if (!cmdText) return;

    const timestamp = new Date().toLocaleTimeString();
    const commandLogs = [`[${timestamp}] console@sec-ai:~# ${cmdText}`];
    const cmd = cmdText.toLowerCase();

    if (cmd === 'clear') {
      clearConsole();
      setInputValue('');
      return;
    } else if (cmd === 'help') {
      commandLogs.push(
        '[OK] Available terminal operations:',
        ' - status : Fetch active network and model diagnostics.',
        ' - route  : Show current route mapping.',
        ' - clean  : Execute system RAM sweep.',
        ' - about  : Engine telemetry specifications.',
        ' - clear  : Wipe active terminal records.'
      );
    } else if (cmd === 'about') {
      commandLogs.push(
        '[OK] STEALTH-SECURITY AI-IDS SYSTEMS [v78.2]',
        ' - Core: Deep Ensemble classifier model.',
        ' - Explainer: Explainable AI heuristics via Groq.',
        ' - Status: active capture on network interface.'
      );
    } else if (cmd === 'status') {
      commandLogs.push(
        '[OK] Operational Diagnostics:',
        ' - Network: STABLE | Latency: 4ms',
        ' - Neural Score: Composite Threat Index nominal',
        ' - CPU Core Temp: 49.2°C | RAM Sync: 100%'
      );
    } else if (cmd === 'route') {
      commandLogs.push(`[OK] Routing: Current resolved client state = ${location.pathname}`);
    } else if (cmd === 'clean') {
      commandLogs.push(
        '[SYS] Executing RAM collection sweep...',
        '[OK] Cleared 104MB cache buffer. Systems operating at peak.'
      );
    } else if (cmd === 'hello') {
      commandLogs.push('[OK] Hello Admin. Terminal communication link is secure.');
    } else {
      commandLogs.push(`[WARN] Command not recognized: '${cmdText}'. Type 'help' for options.`);
    }

    setLogs(prev => [...prev, ...commandLogs].slice(-45));
    setInputValue('');
  };

  if (!isOpen) {
    return (
      <button 
        onClick={() => setIsOpen(true)}
        className="system-terminal-badge"
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.borderColor = 'var(--accent-blue)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.borderColor = 'var(--accent-blue-soft)';
        }}
      >
        <span className="status-pulse" style={{ background: 'var(--accent-blue)', width: '6px', height: '6px' }}></span>
        [ SYS CONSOLE ]
      </button>
    );
  }

  return (
    <div 
      className="system-terminal-panel"
      onClick={() => inputRef.current && inputRef.current.focus()}
    >
      {/* Console Header */}
      <div 
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '10px 16px',
          background: 'rgba(255,255,255,0.02)',
          borderBottom: '1px solid var(--border-color)',
          userSelect: 'none'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)', fontWeight: '800', letterSpacing: '0.5px' }}>
          <span className="status-pulse" style={{ background: 'var(--accent-cyan)', width: '6px', height: '6px' }}></span>
          SYSTEM CONSOLE v78.2
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <button 
            onClick={clearConsole} 
            title="Clear Logs"
            style={{ background: 'none', border: 'none', color: '#52525b', cursor: 'pointer', fontSize: '9px', fontWeight: '800' }}
            onMouseEnter={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
            onMouseLeave={(e) => e.currentTarget.style.color = '#52525b'}
          >
            CLEAR
          </button>
          <button 
            onClick={(e) => {
              e.stopPropagation();
              setIsOpen(false);
            }}
            style={{ background: 'none', border: 'none', color: '#52525b', cursor: 'pointer', fontSize: '13px', padding: 0 }}
            onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-red)'}
            onMouseLeave={(e) => e.currentTarget.style.color = '#52525b'}
          >
            &times;
          </button>
        </div>
      </div>

      {/* Console Output logs body */}
      <div 
        style={{
          flex: 1,
          padding: '16px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
          lineHeight: '1.4'
        }}
      >
        {logs.map((log, idx) => {
          let logColor = '#a1a1aa'; // default greyish
          if (log.includes('[BOOT]')) logColor = '#60a5fa'; // neon blue
          else if (log.includes('[OK]')) logColor = 'var(--accent-green)'; // neon green
          else if (log.includes('[WARN]')) logColor = 'var(--accent-orange)'; // neon amber
          else if (log.includes('[ROUTE]')) logColor = 'var(--accent-cyan)'; // cyan
          
          return (
            <div key={idx} style={{ color: logColor, wordBreak: 'break-all' }}>
              {log}
            </div>
          );
        })}
        
        {/* Interactive Shell Command Form */}
        <form 
          onSubmit={handleCommandSubmit}
          style={{ display: 'flex', alignItems: 'center', width: '100%', marginTop: '4px' }}
        >
          <span style={{ color: 'var(--accent-green)', marginRight: '6px', whiteSpace: 'nowrap' }}>
            console@sec-ai:~#
          </span>
          <input
            ref={inputRef}
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            style={{
              flex: 1,
              background: 'none',
              border: 'none',
              outline: 'none',
              color: 'var(--accent-green)',
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '11px',
              padding: 0,
              caretColor: 'var(--accent-green)'
            }}
          />
        </form>
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
