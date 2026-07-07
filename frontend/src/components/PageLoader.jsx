import { useEffect, useRef, useState } from 'react'
import lottie from 'lottie-web'

export default function PageLoader({ onComplete, isRouteTransition = false }) {
  const containerRef = useRef(null)
  const [logs, setLogs] = useState([])
  const [isFading, setIsFading] = useState(false)

  useEffect(() => {
    // Load lottie animation from public asset directory
    const anim = lottie.loadAnimation({
      container: containerRef.current,
      renderer: 'svg',
      loop: true,
      autoplay: true,
      path: '/Security.json'
    })

    const logsSequence = isRouteTransition ? [
      'CONNECTING INTERFACE PIPELINE...',
      'VERIFYING SEGMENT PERMISSIONS...',
      'RESOLVING MODULE RENDER...'
    ] : [
      'BOOTSTRAPPING SECURE MATRIX HOST...',
      'ESTABLISHING SHIELD ENCRYPTION ROUTERS...',
      'COMMENCING SCAPY PORT HANDSHAKES...',
      'DESERIALIZING ENSEMBLE NEURAL NODES...',
      'SYNCHRONIZING ATTACK IP BAN POLICIES...',
      'DECRYPTING ADMIN DASHBOARD TERMINALS...',
      'MATRIX SYSTEMS ONLINE.'
    ]

    const delay = isRouteTransition ? 75 : 220
    const fadeOutDelay = isRouteTransition ? 100 : 600

    let currentLogIdx = 0
    const logTimer = setInterval(() => {
      if (currentLogIdx < logsSequence.length) {
        setLogs(prev => [...prev, isRouteTransition ? `[ROUTE] ${logsSequence[currentLogIdx]}` : `[OK] ${logsSequence[currentLogIdx]}`])
        currentLogIdx++
      } else {
        clearInterval(logTimer)
        // Wait a small delay then begin fade out transition
        setTimeout(() => {
          setIsFading(true)
          setTimeout(() => {
            if (onComplete) onComplete()
          }, 600) // matches transition duration in CSS
        }, fadeOutDelay)
      }
    }, delay)

    return () => {
      anim.destroy()
      clearInterval(logTimer)
    }
  }, [onComplete, isRouteTransition])

  return (
    <div className={`boot-loader-overlay ${isRouteTransition ? 'route-transit-overlay' : ''} ${isFading ? 'fade-out' : ''}`}>

      <div className="boot-loader-content">
        
        {/* Glowing Lottie Container */}
        <div ref={containerRef} className="boot-lottie-container" />
        
        <h2 className="boot-loader-title">{isRouteTransition ? 'DECRYPTING SEGMENT' : 'CyberMatrix Defense Secure'}</h2>
        <span className="boot-loader-subtitle">{isRouteTransition ? 'RESOLVING GATEWAY CORE TARGET' : 'ML SECURITY SYSTEM SHIELD BOOT'}</span>
      </div>
    </div>
  )
}
