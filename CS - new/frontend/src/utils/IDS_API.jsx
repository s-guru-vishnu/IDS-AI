export const API_BASE = 'http://localhost:5000/api';

export async function fetchAPI(endpoint) {
    const res = await fetch(`${API_BASE}${endpoint}`);
    if (!res.ok) throw new Error(`API Error: ${res.status}`);
    return res.json();
}

export function getRiskLevel(risk) {
    if (risk >= 0.8) return { label: 'CRITICAL', color: '#dc2626' };
    if (risk >= 0.5) return { label: 'HIGH', color: '#d97706' };
    if (risk >= 0.2) return { label: 'MEDIUM', color: '#0891b2' };
    return { label: 'LOW', color: '#059669' };
}

export function getDecisionClass(decision) {
    return decision === 'BLOCK' ? 'badge-block' : 'badge-allow';
}

/**
 * 🎨 PRECISE ARCHITECTURAL ICONS (Human-Crafted Look)
 * Using thin strokes (1.5), layered paths, and zero emojis.
 */
const AttackIcons = {
    DDoS: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5M2 12l10 5 10-5" opacity="0.5" />
            <circle cx="12" cy="7" r="1" fill={c} />
        </svg>
    ),
    DoS: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M15 9l-6 6M9 9l6 6" />
        </svg>
    ),
    MITM: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M23 21v-2a4 4 0 0 0-3-3.87" opacity="0.4" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" opacity="0.4" />
        </svg>
    ),
    Scan: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
            <path d="M11 8a3 3 0 0 1 3 3" opacity="0.6" />
        </svg>
    ),
    Normal: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
        </svg>
    ),
    Festival: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
            <line x1="4" y1="22" x2="4" y2="15" />
        </svg>
    ),
    Slowloris: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
            <path d="M12 2v2M12 20v2M2 12h2M20 12h2" opacity="0.3" />
        </svg>
    ),
    Injection: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
        </svg>
    ),
    Mixed: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
            <path d="M12 22V12" opacity="0.5" />
        </svg>
    ),
    SYN: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="m13 2-2 2.5h3L12 7h3L11 11h3L9 16l1 2-7-7h4L10 2Z" />
            <path d="m17 14 5-5-1.5-1.5" opacity="0.4" />
            <path d="M14 19h5" opacity="0.4" />
        </svg>
    ),
    Generic: (c) => (
        <svg viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
            <path d="M9 9h6v6H9z" opacity="0.5" />
        </svg>
    ),
};

export function getAttackColor(type = '') {
    const t = type.toLowerCase();
    
    // Core color mapping
    if (t.includes('ddos') || t.includes('tcp volumetric') || t.includes('udp volumetric')) 
        return { color: '#dc2626', bg: 'var(--accent-red-soft)', icon: AttackIcons.DDoS('#dc2626') };
    
    if (t.includes('dos')) 
        return { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.08)', icon: AttackIcons.DoS('#ef4444') };
    
    if (t.includes('mitm') || t.includes('arp')) 
        return { color: '#7c3aed', bg: 'var(--accent-purple-soft)', icon: AttackIcons.MITM('#7c3aed') };
    
    if (t.includes('scan')) 
        return { color: '#0891b2', bg: 'var(--accent-cyan-soft)', icon: AttackIcons.Scan('#0891b2') };
    
    if (t.includes('normal')) 
        return { color: '#059669', bg: 'var(--accent-green-soft)', icon: AttackIcons.Normal('#059669') };
    
    if (t.includes('festival')) 
        return { color: '#10b981', bg: 'rgba(16, 185, 129, 0.08)', icon: AttackIcons.Festival('#10b981') };
    
    if (t.includes('slowloris') || t.includes('stretch')) 
        return { color: '#d97706', bg: 'var(--accent-orange-soft)', icon: AttackIcons.Slowloris('#d97706') };
    
    if (t.includes('injection') || t.includes('waf')) 
        return { color: '#be123c', bg: 'rgba(190, 18, 60, 0.08)', icon: AttackIcons.Injection('#be123c') };
    
    if (t.includes('mixed') || t.includes('chaos')) 
        return { color: '#db2777', bg: 'rgba(219, 39, 119, 0.08)', icon: AttackIcons.Mixed('#db2777') };
    
    if (t.includes('syn flood') || t.includes('half-open')) 
        return { color: '#e11d48', bg: 'rgba(225, 29, 72, 0.08)', icon: AttackIcons.SYN('#e11d48') };

    return { color: '#4f46e5', bg: 'var(--accent-blue-soft)', icon: AttackIcons.Generic('#4f46e5') };
}
