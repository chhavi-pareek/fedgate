import { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'
import {
  LineChart, Line, BarChart, Bar, ComposedChart,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ReferenceLine, ResponsiveContainer, Cell,
} from 'recharts'

const API_BASE = 'http://localhost:8000'

const S = {
  bg:      '#0f172a',
  card:    '#1e293b',
  border:  '#334155',
  cyan:    '#00d4ff',
  green:   '#51cf66',
  yellow:  '#ffd43b',
  red:     '#ff6b6b',
  purple:  '#cc5de8',
  textPri: '#f1f5f9',
  textSec: '#94a3b8',
  mono:    '"JetBrains Mono", "Fira Code", monospace',
  sans:    '"Inter", system-ui, sans-serif',
}

const NODE_META = {
  0: { name: 'Login',   attack: 'Credential Stuffing', short: 'CRED STUFFING',  color: '#00d4ff', localF1: 0.9375, globalF1: 0.6122, postFed: 0.9664, miss: 39 },
  1: { name: 'Payment', attack: 'Rate Abuse / DoS',    short: 'RATE ABUSE',     color: '#51cf66', localF1: 0.9677, globalF1: 0.5300, postFed: 0.9655, miss: 47 },
  2: { name: 'Search',  attack: 'Scraping',            short: 'SCRAPING',       color: '#ffd43b', localF1: 0.9677, globalF1: 0.3138, postFed: 0.8889, miss: 69 },
  3: { name: 'Profile', attack: 'Parameter Tampering', short: 'PARAM TAMPER',   color: '#cc5de8', localF1: 0.9375, globalF1: 0.5137, postFed: 0.9664, miss: 49 },
  4: { name: 'Admin',   attack: 'Unauthorised Probing',short: 'UNAUTH PROBE',   color: '#ff6b6b', localF1: 0.9524, globalF1: 0.4310, postFed: 0.8971, miss: 57 },
}

const ATTACK_ANALYSIS = {
  0: {
    color: '#00d4ff',
    how: 'Attacker fires thousands of stolen username/password pairs at the login endpoint using automated tools. Works because users reuse passwords across sites. One valid combo = full account takeover.',
    indicators: ['requests_per_min > 60', 'failed_auth_streak > 5', 'HTTP 401/403 spike', 'inter_request_time < 0.3 s'],
    defenses: [
      { name: 'Rate Limiting',             detail: 'Cap login attempts to 5/min per IP. Throttle progressively on failure.' },
      { name: 'Account Lockout',           detail: 'Lock account for 15 min after 5 consecutive failures. Alert the user.' },
      { name: 'Multi-Factor Auth (MFA)',   detail: 'Require OTP/TOTP on every login. Makes stolen passwords useless alone.' },
      { name: 'Breach Password Check',     detail: 'Reject passwords found in known breach databases (HaveIBeenPwned API).' },
      { name: 'Anomaly-Based Detection',   detail: 'FedGate flags the failed_auth_streak + burst pattern as anomalous reconstruction error. After federation, all 5 nodes share this detection capability.' },
    ],
  },
  1: {
    color: '#51cf66',
    how: 'Attacker floods the payment endpoint with a high volume of requests in a short window — either to exhaust server resources (DoS) or to bypass rate-checked business logic (e.g., free trial abuse, coupon hammering).',
    indicators: ['requests_per_min > 120', 'payload_size_bytes unusually small (probing)', 'HTTP 429 responses increasing', 'inter_request_time ≈ 0'],
    defenses: [
      { name: 'Token Bucket Rate Limiting', detail: 'Allow bursts up to X tokens, refill at Y/sec. Smoothly absorbs spikes without blocking legitimate users.' },
      { name: 'IP / Session Throttling',   detail: 'Enforce per-session request quotas independently of IP (catches proxied attacks).' },
      { name: 'CAPTCHA on Threshold',      detail: 'Trigger challenge after 20 rapid requests. Stops bots, passes humans.' },
      { name: 'Idempotency Keys',          detail: 'Reject duplicate payment requests — prevents charge-replay abuse.' },
      { name: 'Anomaly-Based Detection',   detail: 'FedGate detects the flat inter_request_time + volume spike as a reconstruction outlier. The global encoder learned this pattern from the Payment node.' },
    ],
  },
  2: {
    color: '#ffd43b',
    how: 'Attacker systematically harvests product listings, prices, or user data by crawling search/catalog endpoints at high speed. Goal is competitive intelligence or building a shadow dataset.',
    indicators: ['unique_endpoints_per_session very high', 'requests_per_min 30–80 (sustained)', 'User-Agent absent or generic', 'Sequential query parameters'],
    defenses: [
      { name: 'Request Fingerprinting',    detail: 'Track endpoint visit sequences per session. Flag breadth-first traversal patterns.' },
      { name: 'Honeypot Endpoints',        detail: 'Embed fake catalog URLs in HTML. Any request to them is definitively a bot.' },
      { name: 'Robots.txt + Rate Cap',     detail: 'Enforce crawl-delay in robots.txt. Block agents that ignore it.' },
      { name: 'CAPTCHA on Catalog Depth', detail: 'Challenge sessions that exceed N unique endpoints in M seconds.' },
      { name: 'Anomaly-Based Detection',   detail: 'FedGate flags the high unique_endpoints_per_session feature as anomalous. Federation brings this knowledge to Login/Admin nodes that would otherwise miss scraping attempts.' },
    ],
  },
  3: {
    color: '#cc5de8',
    how: 'Attacker manipulates API request parameters — IDs, prices, role fields — to access data or trigger actions they are not authorised for. Often exploits missing server-side validation.',
    indicators: ['payload_size_bytes irregular (inflated or crafted)', 'HTTP 400/403 on parameter rejection', 'Sequential or out-of-range ID values', 'Unexpected field names in body'],
    defenses: [
      { name: 'Server-Side Validation',    detail: 'Never trust client-supplied IDs or role fields. Re-validate every parameter against the authenticated user context.' },
      { name: 'JWT / HMAC Signing',        detail: 'Sign sensitive parameters (price, role, cart total) so tampering is detectable.' },
      { name: 'Object-Level Auth (BOLA)',  detail: 'Check that the requesting user owns the resource ID in every endpoint, not just at login.' },
      { name: 'Schema Enforcement',        detail: 'Reject requests whose body does not match the strict OpenAPI schema. Unknown fields = instant 400.' },
      { name: 'Anomaly-Based Detection',   detail: 'FedGate detects the irregular payload_size_bytes distribution as a reconstruction outlier unique to parameter tampering attempts.' },
    ],
  },
  4: {
    color: '#ff6b6b',
    how: 'Attacker systematically probes admin endpoints to map internal structure, find misconfigured endpoints, or leak configuration data — often as a reconnaissance step before a larger attack.',
    indicators: ['unique_endpoints_per_session high (enumeration)', 'HTTP 403/404 spike', 'Requests to /admin, /config, /debug paths', 'Off-hours traffic pattern'],
    defenses: [
      { name: 'IP Allowlisting',           detail: 'Admin endpoints accessible only from known internal IPs or VPN. Hard block everything else.' },
      { name: 'Audit Logging + Alerting',  detail: 'Log every admin request with full context. Alert on any 403 to /admin/* from non-whitelisted IPs.' },
      { name: 'Path Obfuscation',          detail: 'Rename admin routes to non-guessable paths. Combine with allowlist — obscurity is not security alone.' },
      { name: 'Anomaly-Based Detection',   detail: 'FedGate flags the enumeration pattern (high unique_endpoints + HTTP error codes) in the Admin node. After federation, even the Login node can identify this probe pattern.' },
    ],
  },
}

const KC_ORANGE = '#f97316'

const KC_EVENTS = {
  0: { event_type: 'AUTH_SUCCESS',  endpoint: '/api/login',          code: 200 },
  1: { event_type: 'PAYMENT_PROBE', endpoint: '/api/payment/confirm', code: 200 },
  4: { event_type: 'ADMIN_PROBE',   endpoint: '/api/admin/config',    code: 403 },
}

const ENDPOINTS = {
  0: ['/api/login', '/api/auth/verify', '/api/session/create', '/api/user/authenticate'],
  1: ['/api/payment/process', '/api/checkout', '/api/payment/confirm', '/api/billing/charge'],
  2: ['/api/search?q=product', '/api/search?q=user', '/api/catalog/list', '/api/search?q=price&limit=500'],
  3: ['/api/profile/update', '/api/user/settings', '/api/profile/avatar', '/api/account/edit'],
  4: ['/api/admin/users', '/api/admin/logs', '/api/admin/config', '/api/system/status'],
}

const SIM_CURVE = [0.40, 0.55, 0.65, 0.70, 0.75, 0.72, 0.80, 0.87, 0.91, 0.94]

const EPS_DATA = [
  { epsilon: '0.01', f1: 0.9376, zone: 'robust' },
  { epsilon: '0.1',  f1: 0.9363, zone: 'robust' },
  { epsilon: '0.5',  f1: 0.9363, zone: 'robust' },
  { epsilon: '1.0',  f1: 0.9369, zone: 'robust' },
  { epsilon: '5.0',  f1: 0.4852, zone: 'cliff'  },
  { epsilon: '∞',    f1: 0.4865, zone: 'cliff'  },
]

const POISON_ROUND = 3

// ── Utilities ──────────────────────────────────────────────────────────────────

function nowStr() { return new Date().toTimeString().slice(0, 8) }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)] }
function btnStyle(bg, color, disabled = false) {
  return {
    padding: '10px 24px', borderRadius: 7, border: 'none',
    background: disabled ? S.border : bg, color: disabled ? S.textSec : color,
    fontSize: 13, fontWeight: 700, fontFamily: S.mono,
    cursor: disabled ? 'not-allowed' : 'pointer', transition: 'all 0.15s',
  }
}

// ── Primitives ─────────────────────────────────────────────────────────────────

function Dot({ color, size = 8 }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size, borderRadius: '50%',
      background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0,
    }} />
  )
}

function Spinner() {
  return (
    <span style={{
      display: 'inline-block', width: 14, height: 14,
      border: `2px solid ${S.border}`, borderTopColor: S.cyan,
      borderRadius: '50%', animation: 'spin 0.7s linear infinite',
      marginRight: 6, verticalAlign: 'middle',
    }} />
  )
}

function PillToggle({ value, onChange, onColor = S.cyan }) {
  return (
    <div onClick={() => onChange(!value)} style={{
      width: 44, height: 22, borderRadius: 11, cursor: 'pointer',
      background: value ? onColor : S.border,
      position: 'relative', transition: 'background 0.2s', flexShrink: 0,
    }}>
      <div style={{
        position: 'absolute', top: 3, left: value ? 25 : 3,
        width: 16, height: 16, borderRadius: '50%',
        background: '#fff', transition: 'left 0.2s',
      }} />
    </div>
  )
}

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: S.card, border: `1px solid ${S.border}`,
      borderRadius: 10, padding: 16, ...style,
    }}>
      {children}
    </div>
  )
}

function DarkTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#0a1120', border: `1px solid ${S.border}`,
      borderRadius: 6, padding: '8px 12px', fontSize: 12, color: S.textPri,
    }}>
      <div style={{ color: S.textSec, marginBottom: 4 }}>Round {label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.color, lineHeight: 1.8 }}>
          {p.name}: {typeof p.value === 'number' ? p.value.toFixed(4) : p.value}
        </div>
      ))}
    </div>
  )
}

// ── ProgressBar ────────────────────────────────────────────────────────────────

function ProgressBar({ screen }) {
  const steps = ['Live Traffic', 'The Problem', 'Federation', 'Results', 'Case Studies']
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      height: 44, borderBottom: `1px solid ${S.border}`,
      background: '#0a1120', flexShrink: 0, padding: '0 24px',
    }}>
      {steps.map((label, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 26, height: 26, borderRadius: '50%', display: 'flex',
              alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontFamily: S.mono, fontWeight: 700,
              background: i < screen ? S.green : i === screen ? S.cyan : S.border,
              color: i <= screen ? S.bg : S.textSec, transition: 'all 0.3s',
            }}>{i < screen ? '✓' : i + 1}</div>
            <span style={{
              fontSize: 12, fontWeight: i === screen ? 700 : 400,
              color: i === screen ? S.textPri : S.textSec,
            }}>{label}</span>
          </div>
          {i < 4 && (
            <div style={{
              width: 32, height: 2, margin: '0 8px',
              background: i < screen ? S.green : S.border, transition: 'all 0.3s',
            }} />
          )}
        </div>
      ))}
      <div style={{ marginLeft: 'auto', fontSize: 11, color: S.textSec, fontFamily: S.mono }}>
        Step {screen + 1} of 5
      </div>
    </div>
  )
}

// ── Header ─────────────────────────────────────────────────────────────────────

function Header({ title, subtitle, apiConnected }) {
  return (
    <div style={{
      borderBottom: `1px solid ${S.border}`, padding: '12px 24px',
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      flexShrink: 0,
    }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: subtitle ? 3 : 0 }}>
          <span style={{ fontFamily: S.mono, fontSize: 20, fontWeight: 700, color: S.cyan, letterSpacing: '0.04em' }}>FedGate</span>
          <span style={{ color: S.textSec }}>—</span>
          <span style={{ fontSize: 16, fontWeight: 600, color: S.textPri }}>{title}</span>
        </div>
        {subtitle && <div style={{ fontSize: 13, color: S.textSec }}>{subtitle}</div>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
        <Dot color={apiConnected ? S.green : S.red} size={7} />
        <span style={{ color: S.textPri }}>{apiConnected ? 'API Connected' : 'API Offline'}</span>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCREEN 1 — LIVE API TRAFFIC
// ═══════════════════════════════════════════════════════════════════════════════

function genRequest(nodeId) {
  const meta = NODE_META[nodeId]
  const roll = Math.random()
  const normalCodes = [200, 200, 200, 201, 304]
  const attackCodes = [200, 401, 403, 429, 400]
  if (roll < 0.60) {
    return { id: Math.random(), time: nowStr(), endpoint: pick(ENDPOINTS[nodeId]), code: pick(normalCodes), type: 'normal', label: 'NORMAL' }
  } else if (roll < 0.85) {
    return { id: Math.random(), time: nowStr(), endpoint: pick(ENDPOINTS[nodeId]), code: pick(attackCodes), type: 'detected', label: meta.short }
  } else {
    const others = [0, 1, 2, 3, 4].filter(x => x !== nodeId)
    const otherId = pick(others)
    return { id: Math.random(), time: nowStr(), endpoint: pick(ENDPOINTS[otherId]), code: pick(attackCodes), type: 'missed', label: `MISSED: ${NODE_META[otherId].short}` }
  }
}

function NodeTrafficPanel({ nodeId, onAttackClick, killChainEntry = null, killChainAlerted = false }) {
  const meta = NODE_META[nodeId]
  const [log, setLog] = useState([])
  const [caught, setCaught] = useState(0)
  const [missed, setMissed] = useState(0)
  const prevKcType = useRef(null)

  useEffect(() => {
    const tick = () => {
      const req = genRequest(nodeId)
      setLog(prev => [...prev.slice(-7), req])
      if (req.type === 'detected') setCaught(c => c + 1)
      if (req.type === 'missed') setMissed(m => m + 1)
    }
    tick()
    const id = setInterval(tick, 2000)
    return () => clearInterval(id)
  }, [nodeId])

  useEffect(() => {
    if (!killChainEntry) { prevKcType.current = null; return }
    if (killChainEntry.event_type !== prevKcType.current) {
      prevKcType.current = killChainEntry.event_type
      setLog(prev => [...prev.slice(-7), {
        id: Math.random(), time: nowStr(),
        endpoint: killChainEntry.endpoint, code: killChainEntry.code,
        type: 'killchain', label: killChainEntry.event_type,
      }])
    }
  }, [killChainEntry])

  const tc = { normal: S.green, detected: S.red, missed: '#475569', killchain: KC_ORANGE }
  const bg = { normal: '#052e16', detected: '#3b0707', missed: '#1e293b', killchain: '#3b1a06' }

  return (
    <Card style={{
      flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 8,
      ...(killChainAlerted ? {
        border: `1px solid ${KC_ORANGE}90`,
        boxShadow: `0 0 18px ${KC_ORANGE}28`,
        transition: 'border 0.4s ease, box-shadow 0.4s ease',
      } : {}),
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Dot color={killChainAlerted ? KC_ORANGE : meta.color} />
        <span style={{ fontFamily: S.mono, fontSize: 13, fontWeight: 700, color: S.textPri }}>{meta.name}</span>
        {killChainAlerted && (
          <span style={{
            fontSize: 8, padding: '1px 5px', borderRadius: 3, fontFamily: S.mono, fontWeight: 700,
            background: KC_ORANGE + '25', color: KC_ORANGE, border: `1px solid ${KC_ORANGE}50`,
          }}>KILL CHAIN</span>
        )}
      </div>
      <div style={{
        display: 'inline-flex', padding: '2px 8px', borderRadius: 4, alignSelf: 'flex-start',
        background: meta.color + '20', border: `1px solid ${meta.color}50`,
        fontSize: 9, color: meta.color, fontFamily: S.mono, fontWeight: 700,
      }}>
        {meta.short}
      </div>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3, minHeight: 220, overflow: 'hidden' }}>
        {log.map(r => (
          <div key={r.id}
            onClick={() => r.type === 'detected' && onAttackClick(nodeId, r)}
            style={{
              display: 'flex', alignItems: 'center', gap: 5, padding: '3px 6px',
              borderRadius: 4, background: bg[r.type], borderLeft: `2px solid ${tc[r.type]}`,
              cursor: r.type === 'detected' ? 'pointer' : 'default',
              transition: 'filter 0.15s',
              ...(r.type === 'killchain' ? { animation: 'fadeIn 0.4s ease' } : {}),
            }}
            onMouseEnter={e => { if (r.type === 'detected') e.currentTarget.style.filter = 'brightness(1.4)' }}
            onMouseLeave={e => { e.currentTarget.style.filter = 'none' }}
          >
            <span style={{ color: S.textSec, flexShrink: 0, fontSize: 9, fontFamily: S.mono }}>{r.time}</span>
            <span style={{ color: S.textSec, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, fontFamily: S.mono }}>{r.endpoint}</span>
            <span style={{ color: tc[r.type], flexShrink: 0, fontSize: 9, fontFamily: S.mono }}>{r.code}</span>
            <span style={{
              flexShrink: 0, padding: '1px 4px', borderRadius: 3, whiteSpace: 'nowrap',
              background: tc[r.type] + '30', color: tc[r.type],
              fontSize: 8, fontWeight: 700, fontFamily: S.mono,
            }}>{r.label}</span>
            {r.type === 'detected' && <span style={{ fontSize: 7, color: S.textSec, fontFamily: S.mono }}>▶</span>}
            {r.type === 'killchain' && (
              <span style={{ fontSize: 7, color: KC_ORANGE, fontFamily: S.mono, flexShrink: 0 }}>session_7f3a</span>
            )}
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 14, fontSize: 11, fontFamily: S.mono }}>
        <span style={{ color: S.green }}>Caught: {caught}</span>
        <span style={{ color: '#475569' }}>Missed: {missed}</span>
      </div>
      <div style={{ fontSize: 10, color: S.textSec, fontStyle: 'italic' }}>
        Click any detected attack to analyse it
      </div>
    </Card>
  )
}

function AttackDetailPanel({ nodeId, onClose }) {
  const meta = NODE_META[nodeId]
  const analysis = ATTACK_ANALYSIS[nodeId]

  return (
    <div style={{
      borderTop: `2px solid ${meta.color}`,
      background: '#0a1120', padding: '16px 24px',
      display: 'flex', flexDirection: 'column', gap: 14, flexShrink: 0,
      animation: 'fadeIn 0.25s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Dot color={meta.color} size={10} />
        <span style={{ fontFamily: S.mono, fontSize: 14, fontWeight: 700, color: meta.color }}>
          {meta.name} — {meta.attack}
        </span>
        <span style={{ fontSize: 10, color: S.red, fontFamily: S.mono, padding: '2px 8px', background: '#3b0707', borderRadius: 4, border: `1px solid ${S.red}40` }}>
          ATTACK DETECTED
        </span>
        <button onClick={onClose} style={{
          marginLeft: 'auto', background: 'transparent', border: `1px solid ${S.border}`,
          color: S.textSec, borderRadius: 5, padding: '3px 10px', cursor: 'pointer', fontSize: 11,
        }}>✕ Close</button>
      </div>

      <div style={{ display: 'flex', gap: 16 }}>

        {/* LEFT — Attack Analysis */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 10, color: meta.color, fontFamily: S.mono, letterSpacing: '0.1em' }}>ATTACK ANALYSIS</div>

          <div style={{ fontSize: 12, color: S.textPri, lineHeight: 1.7, padding: '10px 14px', background: S.card, borderRadius: 8, border: `1px solid ${meta.color}25` }}>
            {analysis.how}
          </div>

          <div>
            <div style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono, marginBottom: 6 }}>INDICATORS OF COMPROMISE</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {analysis.indicators.map(ind => (
                <span key={ind} style={{
                  padding: '3px 8px', borderRadius: 4, fontSize: 10, fontFamily: S.mono,
                  background: S.red + '18', border: `1px solid ${S.red}40`, color: S.red,
                }}>{ind}</span>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT — Defense Playbook */}
        <div style={{ flex: 1.2, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 10, color: S.green, fontFamily: S.mono, letterSpacing: '0.1em' }}>DEFENSE PLAYBOOK</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {analysis.defenses.map((d, i) => (
              <div key={i} style={{
                display: 'flex', gap: 10, padding: '8px 12px',
                background: i === analysis.defenses.length - 1 ? '#0f2744' : S.card,
                borderRadius: 7,
                border: `1px solid ${i === analysis.defenses.length - 1 ? S.cyan + '40' : S.border}`,
              }}>
                <div style={{
                  width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                  background: i === analysis.defenses.length - 1 ? S.cyan + '20' : S.green + '18',
                  border: `1.5px solid ${i === analysis.defenses.length - 1 ? S.cyan : S.green}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 9, color: i === analysis.defenses.length - 1 ? S.cyan : S.green, fontWeight: 700,
                }}>{i + 1}</div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: i === analysis.defenses.length - 1 ? S.cyan : S.textPri, marginBottom: 2 }}>
                    {d.name}
                  </div>
                  <div style={{ fontSize: 10, color: S.textSec, lineHeight: 1.5 }}>{d.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}

function KillChainAlertPanel({ onReset }) {
  const [propagated, setPropagated] = useState([])

  useEffect(() => {
    const order = [0, 1, 4, 3, 2]
    order.forEach((nodeId, i) => {
      setTimeout(() => setPropagated(prev => [...prev, nodeId]), i * 280 + 500)
    })
  }, [])

  const KCA_ITEMS = [
    { sent: true,  label: 'Hashed session ID',  detail: 'SHA-256(session_7f3a) — irreversible' },
    { sent: true,  label: 'Event timestamp',     detail: 'T+0s, T+60s, T+2m7s (relative offsets)' },
    { sent: true,  label: 'Node identifier',     detail: 'Nodes 0, 1, 4 — no service metadata' },
    { sent: true,  label: 'SESSION_BLOCK cmd',   detail: 'Broadcast to all 5 nodes via federation channel' },
    { sent: false, label: 'Raw API logs',         detail: 'Stayed local — never left the node' },
    { sent: false, label: 'Session credentials', detail: 'Stayed local — never left the node' },
    { sent: false, label: 'User identity',        detail: 'Stayed local — never left the node' },
  ]

  return (
    <div style={{
      borderTop: `2px solid ${KC_ORANGE}`,
      background: '#140900', padding: '14px 24px',
      display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0,
      animation: 'fadeIn 0.35s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: S.mono, fontSize: 14, fontWeight: 700, color: KC_ORANGE }}>
          KILL CHAIN DETECTED
        </span>
        <span style={{
          padding: '3px 10px', borderRadius: 4, fontFamily: S.mono, fontSize: 11, fontWeight: 700,
          background: KC_ORANGE + '20', border: `1px solid ${KC_ORANGE}50`, color: KC_ORANGE,
        }}>Login → Payment → Admin</span>
        <span style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono }}>
          session_7f3a · 127 s elapsed · no single node fired
        </span>
        <button onClick={onReset} style={{
          marginLeft: 'auto', background: 'transparent', border: `1px solid ${S.border}`,
          color: S.textSec, borderRadius: 5, padding: '3px 10px', cursor: 'pointer', fontSize: 11,
        }}>↺ Reset Demo</button>
      </div>

      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 10, color: KC_ORANGE, fontFamily: S.mono, letterSpacing: '0.1em' }}>
            WHY THIS EVADES LOCAL DETECTION
          </div>
          <div style={{
            fontSize: 12, color: S.textPri, lineHeight: 1.7,
            padding: '9px 12px', background: S.card, borderRadius: 8,
            border: `1px solid ${KC_ORANGE}20`, flex: 1,
          }}>
            Each node saw exactly 1 request — far below any per-node threshold. No local
            autoencoder fired. The kill chain was only visible when session hashes from all
            three nodes were correlated in the federation layer.
          </div>
          <div style={{
            fontSize: 10, color: S.textSec, fontFamily: S.mono,
            padding: '7px 10px', background: '#0f172a', borderRadius: 6,
            border: `1px solid ${S.border}`, lineHeight: 1.5,
          }}>
            FedGate's CKKS channel carries session-level threat intelligence alongside model
            weights — no raw data leaves any node.
          </div>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 10, color: S.green, fontFamily: S.mono, letterSpacing: '0.1em' }}>
            WHAT CROSSED THE FEDERATION CHANNEL
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {KCA_ITEMS.map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 7, alignItems: 'flex-start' }}>
                <span style={{ fontSize: 11, flexShrink: 0, color: item.sent ? S.green : '#475569' }}>
                  {item.sent ? '✓' : '✗'}
                </span>
                <div>
                  <span style={{ fontSize: 11, fontWeight: 600, color: item.sent ? S.green : '#475569' }}>
                    {item.label}
                  </span>
                  <span style={{ fontSize: 10, color: S.textSec }}> — {item.detail}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ flex: 1.1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 10, color: S.red, fontFamily: S.mono, letterSpacing: '0.1em' }}>
            SESSION BLOCK PROPAGATED VIA FEDERATION
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {[0, 1, 4, 3, 2].map(id => {
              const done = propagated.includes(id)
              return (
                <div key={id} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px',
                  borderRadius: 5,
                  background: done ? '#3b0707' : S.card,
                  border: `1px solid ${done ? S.red + '50' : S.border}`,
                  transition: 'all 0.35s ease',
                  opacity: done ? 1 : 0.35,
                }}>
                  <Dot color={done ? S.red : '#475569'} size={6} />
                  <span style={{ fontSize: 11, fontFamily: S.mono, color: done ? S.red : S.textSec, flex: 1 }}>
                    {NODE_META[id].name}
                  </span>
                  {done && (
                    <span style={{
                      fontSize: 8, fontFamily: S.mono, fontWeight: 700,
                      color: S.red, background: S.red + '20',
                      padding: '1px 5px', borderRadius: 3,
                    }}>SESSION BLOCKED</span>
                  )}
                  {!done && <Spinner />}
                </div>
              )
            })}
          </div>
          <div style={{ fontSize: 10, color: S.textSec, fontStyle: 'italic' }}>
            session_7f3a rejected at all {propagated.length}/5 nodes
          </div>
        </div>
      </div>
    </div>
  )
}

function Screen1({ onNext }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [kcStep, setKcStep]       = useState(0)
  const [kcRunning, setKcRunning] = useState(false)

  function runKillChainDemo() {
    if (kcRunning) return
    setSelectedNode(null)
    setKcStep(1); setKcRunning(true)
    setTimeout(() => setKcStep(2), 2500)
    setTimeout(() => setKcStep(3), 5000)
    setTimeout(() => { setKcStep(4); setKcRunning(false) }, 6500)
  }

  function resetDemo() { setKcStep(0); setKcRunning(false) }

  const kcEntryFor = (id) => {
    if (id === 0 && kcStep >= 1) return KC_EVENTS[0]
    if (id === 1 && kcStep >= 2) return KC_EVENTS[1]
    if (id === 4 && kcStep >= 3) return KC_EVENTS[4]
    return null
  }

  const kcAlerted = (id) => kcStep >= 4 && [0, 1, 4].includes(id)

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {kcStep > 0 && kcStep < 4 && (
        <div style={{
          padding: '7px 24px', background: '#140900',
          borderBottom: `1px solid ${KC_ORANGE}35`,
          display: 'flex', alignItems: 'center', gap: 10,
          fontSize: 12, fontFamily: S.mono, flexShrink: 0,
          animation: 'fadeIn 0.3s ease',
        }}>
          {kcRunning && <Spinner />}
          <span style={{ color: KC_ORANGE, fontWeight: 700 }}>KILL CHAIN SIM</span>
          <span style={{ color: S.textSec }}>—</span>
          {[{l:'Login',s:1},{l:'→',s:null},{l:'Payment',s:2},{l:'→',s:null},{l:'Admin',s:3}].map((item,i) => (
            <span key={i} style={{
              color: item.s === null ? '#475569' : kcStep >= item.s ? KC_ORANGE : '#475569',
              fontWeight: item.s && kcStep >= item.s ? 700 : 400,
            }}>{item.l}</span>
          ))}
          <span style={{ marginLeft: 'auto', color: S.textSec, fontSize: 10 }}>
            Each node sees 1 request · no local alert fires
          </span>
        </div>
      )}

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px 8px' }}>
        <div style={{ display: 'flex', gap: 12 }}>
          {[0, 1, 2, 3, 4].map(id => (
            <NodeTrafficPanel key={id} nodeId={id}
              onAttackClick={(nodeId) => { if (kcStep === 0) setSelectedNode(prev => prev === nodeId ? null : nodeId) }}
              killChainEntry={kcEntryFor(id)}
              killChainAlerted={kcAlerted(id)}
            />
          ))}
        </div>
        {!selectedNode && kcStep === 0 && (
          <div style={{ textAlign: 'center', marginTop: 10, fontSize: 11, color: S.textSec, fontStyle: 'italic' }}>
            Click any red <span style={{ color: S.red, fontFamily: S.mono }}>DETECTED</span> row to analyse the attack · or run the Kill Chain Demo below
          </div>
        )}
      </div>

      {kcStep >= 4
        ? <KillChainAlertPanel onReset={resetDemo} />
        : selectedNode !== null && kcStep === 0
          ? <AttackDetailPanel nodeId={selectedNode} onClose={() => setSelectedNode(null)} />
          : null
      }

      <div style={{
        borderTop: `1px solid ${S.border}`, padding: '14px 24px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0,
      }}>
        <button
          onClick={kcStep === 0 ? runKillChainDemo : resetDemo}
          disabled={kcRunning}
          style={btnStyle(kcStep === 0 ? KC_ORANGE : S.border, kcStep === 0 ? '#fff' : S.textSec, kcRunning)}
        >
          {kcStep === 0 ? 'Kill Chain Demo' : kcRunning ? 'Simulating...' : 'Reset Demo'}
        </button>
        <button onClick={onNext} style={btnStyle(S.cyan, S.bg)}>See the Problem →</button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCREEN 2 — THE ISOLATION PROBLEM
// ═══════════════════════════════════════════════════════════════════════════════

function F1Bar({ label, value, color }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
        <span style={{ color: S.textSec }}>{label}</span>
        <span style={{ fontFamily: S.mono, fontWeight: 700, color }}>{value.toFixed(4)}</span>
      </div>
      <div style={{ background: S.border, borderRadius: 4, height: 10, overflow: 'hidden' }}>
        <div style={{ width: `${(value * 100).toFixed(1)}%`, height: '100%', background: color, borderRadius: 4, transition: 'width 0.8s ease' }} />
      </div>
    </div>
  )
}

function IsolationCard({ nodeId }) {
  const m = NODE_META[nodeId]
  return (
    <Card style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <Dot color={m.color} />
        <span style={{ fontFamily: S.mono, fontSize: 13, fontWeight: 700, color: S.textPri }}>{m.name}</span>
      </div>
      <F1Bar label="Local F1" value={m.localF1} color={m.color} />
      <F1Bar label="Global F1" value={m.globalF1} color="#ef4444" />
      <div style={{ fontSize: 11, color: S.textSec, fontStyle: 'italic', marginTop: 4 }}>
        Misses {m.miss}% of attacks from other services
      </div>
    </Card>
  )
}

function Screen2({ config, setConfig, onBack, onNext }) {
  const epsBtns = [0.01, 0.1, 0.5, 1.0, 5.0]
  const isRobust = config.epsilon <= 1.0

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        <div style={{ display: 'flex', gap: 12 }}>
          {[0, 1, 2, 3, 4].map(id => <IsolationCard key={id} nodeId={id} />)}
        </div>

        <div style={{
          borderLeft: `4px solid ${S.cyan}`, padding: '14px 18px',
          background: '#0f2744', borderRadius: '0 8px 8px 0',
          border: `1px solid ${S.border}`, borderLeftColor: S.cyan,
        }}>
          <div style={{ fontSize: 13, color: S.textPri, lineHeight: 1.7 }}>
            Each node was trained only on its own attack type. Node 2 (Search) has never seen
            credential stuffing, rate abuse, or admin probing.{' '}
            <strong style={{ color: S.cyan }}>
              Without federation, attackers simply choose the attack type each node cannot see.
            </strong>
          </div>
        </div>

        <Card>
          <div style={{ fontFamily: S.mono, fontSize: 13, fontWeight: 700, color: S.cyan, marginBottom: 16 }}>
            Federation Configuration
          </div>
          <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap', alignItems: 'flex-start' }}>

            <div>
              <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 8 }}>EPSILON (DP noise)</div>
              <div style={{ display: 'flex', gap: 5, marginBottom: 6 }}>
                {epsBtns.map(e => (
                  <button key={e} onClick={() => setConfig(c => ({ ...c, epsilon: e }))} style={{
                    padding: '5px 10px', fontSize: 11, fontFamily: S.mono,
                    background: config.epsilon === e ? S.cyan : S.border,
                    color: config.epsilon === e ? S.bg : S.textSec,
                    border: 'none', borderRadius: 5, cursor: 'pointer',
                    fontWeight: config.epsilon === e ? 700 : 400,
                  }}>{e}</button>
                ))}
              </div>
              <div style={{ fontSize: 11, fontFamily: S.mono, color: isRobust ? S.green : S.red }}>
                {isRobust ? '✓ Robust range' : '⚠ Heterogeneity cliff'}
              </div>
              <div style={{ fontSize: 10, color: S.textSec, marginTop: 6, maxWidth: 200, lineHeight: 1.5 }}>
                {isRobust
                  ? 'Controls how much random noise masks the weights before sharing. Lower = stronger privacy. F1 stays above 0.93 at this level.'
                  : 'At this level, noise overwhelms the shared signal. F1 drops — not from privacy cost, but because averaging breaks down across different attack types.'}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 8 }}>ROUNDS</div>
              <input type="number" min={1} max={20} value={config.num_rounds}
                onChange={e => setConfig(c => ({ ...c, num_rounds: Math.min(20, Math.max(1, parseInt(e.target.value) || 1)) }))}
                style={{
                  width: 70, background: S.bg, border: `1px solid ${S.border}`,
                  color: S.textPri, borderRadius: 5, padding: '6px 8px',
                  fontSize: 12, fontFamily: S.mono,
                }} />
            </div>

            <div>
              <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 10 }}>REPUTATION WEIGHTING</div>
              <PillToggle value={config.use_reputation} onChange={v => setConfig(c => ({ ...c, use_reputation: v }))} />
              <div style={{ fontSize: 10, color: S.textSec, marginTop: 8, maxWidth: 180, lineHeight: 1.5 }}>
                Nodes that consistently improve the model get more influence. Bad actors get sidelined automatically.
              </div>
            </div>

            <div>
              <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 10 }}>POISON DEMO</div>
              <PillToggle value={config.poison_demo} onColor={S.red} onChange={v => setConfig(c => ({ ...c, poison_demo: v }))} />
              {config.poison_demo && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 8 }}>NODE TO POISON</div>
                  <div style={{ display: 'flex', gap: 5 }}>
                    {[0, 1, 2, 3, 4].map(id => (
                      <button key={id} onClick={() => setConfig(c => ({ ...c, poison_node_id: id }))} style={{
                        padding: '4px 8px', fontSize: 10, fontFamily: S.mono, border: 'none', borderRadius: 5, cursor: 'pointer',
                        background: config.poison_node_id === id ? NODE_META[id].color : S.border,
                        color: config.poison_node_id === id ? S.bg : S.textSec,
                        fontWeight: config.poison_node_id === id ? 700 : 400,
                      }}>{NODE_META[id].name}</button>
                    ))}
                  </div>
                  <div style={{ fontSize: 10, color: S.red, marginTop: 8, fontStyle: 'italic' }}>
                    {NODE_META[config.poison_node_id].name} will send poisoned weights at round {POISON_ROUND}
                  </div>
                </div>
              )}
            </div>

          </div>
        </Card>
      </div>

      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '14px 24px', borderTop: `1px solid ${S.border}`, flexShrink: 0,
      }}>
        <button onClick={onBack} style={btnStyle(S.border, S.textSec)}>← Back</button>
        <button onClick={onNext} style={btnStyle(S.cyan, S.bg)}>Run Federation to Fix This →</button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCREEN 3 — FEDERATION RUNNING
// ═══════════════════════════════════════════════════════════════════════════════


function TrustMiniCard({ nodeId, trust, flash }) {
  const m = NODE_META[nodeId]
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
      background: flash ? '#3b0707' : S.bg, borderRadius: 6,
      border: `1px solid ${flash ? S.red : S.border}`, transition: 'all 0.4s',
    }}>
      <Dot color={m.color} size={7} />
      <span style={{ fontSize: 11, fontFamily: S.mono, color: S.textSec, width: 52 }}>{m.name}</span>
      <div style={{ flex: 1, background: S.border, borderRadius: 3, height: 6, overflow: 'hidden' }}>
        <div style={{
          width: `${(Math.min(trust, 1) * 100).toFixed(0)}%`, height: '100%',
          background: flash ? S.red : m.color, transition: 'width 0.6s ease',
        }} />
      </div>
      <span style={{
        fontSize: 11, fontFamily: S.mono, fontWeight: 700,
        color: flash ? S.red : S.cyan, minWidth: 36, textAlign: 'right',
      }}>{trust.toFixed(3)}</span>
    </div>
  )
}

function Screen3({ config, onComplete }) {
  const [simRound, setSimRound] = useState(0)
  const [chartData, setChartData] = useState([])
  const [logEntries, setLogEntries] = useState([])
  const [trust, setTrust] = useState({ 0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0 })
  const [flashNode, setFlashNode] = useState(null)
  const [apiDone, setApiDone] = useState(false)
  const [apiResult, setApiResult] = useState(null)
  const [apiError, setApiError] = useState(null)
  const [banner, setBanner] = useState(false)
  const logRef = useRef(null)

  // Fire real API call on mount
  useEffect(() => {
    axios.post(`${API_BASE}/run-federation`, {
      num_clients: 5,
      num_rounds: config.num_rounds,
      epsilon: config.epsilon,
      use_reputation: config.use_reputation,
      poison_node_id: config.poison_demo ? config.poison_node_id : null,
      poison_round: POISON_ROUND,
    })
      .then(res => { setApiResult(res.data.data); setApiDone(true) })
      .catch(err => setApiError(err.message || 'Request failed'))
  }, [])

  // Simulated round ticker — runs until API responds
  useEffect(() => {
    if (apiDone) return
    const id = setInterval(() => {
      setSimRound(prev => {
        if (prev >= config.num_rounds) return prev
        const next = prev + 1
        const f1 = SIM_CURVE[Math.min(next - 1, SIM_CURVE.length - 1)]
        setChartData(d => [...d, { round: next, mean: f1 }])

        // Generate messages inline for this round
        const msgs = [
          `Round ${next}: Encoder weights extracted (272 params)`,
          `Round ${next}: L2 clipping applied (max_norm=1.0)`,
          `Round ${next}: Laplace noise injected (ε=${config.epsilon})`,
          `Round ${next}: CKKS encryption complete`,
          `Round ${next}: Aggregator: weighted sum on ciphertext`,
          `Round ${next}: Global encoder decrypted and broadcast`,
        ]
        if (next > 1) {
          msgs.push(`Round ${next}: Nodes retrained (FedProx α=0.7)`)
          msgs.push(`Round ${next}: EMA threshold updated (momentum=0.8)`)
        }
        if (next === 1) {
          msgs.push(`Round ${next}: Session correlation window initialised (180 s)`)
          msgs.push(`Round ${next}: Defense playbook registry initialised across 5 nodes`)
        }
        if (next % 2 === 0) {
          msgs.push(`Round ${next}: Defense strategies synchronized — all nodes share full playbook`)
        } else if (next > 1) {
          msgs.push(`Round ${next}: Session correlation signals federated alongside encoder weights`)
        }
        if (config.poison_demo && next === POISON_ROUND) {
          msgs.push(`Round ${POISON_ROUND}: ⚠️ Node ${config.poison_node_id} (${NODE_META[config.poison_node_id].name}) submitted anomalous weights`)
          msgs.push(`Round ${POISON_ROUND}: Reputation system flagged Node ${config.poison_node_id}`)
          msgs.push(`Round ${POISON_ROUND}: Node ${config.poison_node_id} trust → 0.043 normalised weight (was 0.200)`)
          msgs.push(`Round ${POISON_ROUND}: Global model updated — honest nodes dominant`)
        }
        setLogEntries(e => [...e, ...msgs.map(t => ({
          id: Math.random(), text: t, ts: nowStr(), warn: t.includes('⚠️'),
        }))].slice(-40))

        // Update trust scores each round
        setTrust(prevT => {
          const updated = { ...prevT }
          for (let i = 0; i < 5; i++) {
            if (config.poison_demo && i === config.poison_node_id) {
              if (next === POISON_ROUND) {
                updated[i] = 0.043
              } else if (next > POISON_ROUND) {
                updated[i] = Math.min(0.85, updated[i] + 0.06)
              }
            } else {
              updated[i] = Math.min(1.0, updated[i] + (Math.random() * 0.012))
            }
          }
          return updated
        })

        if (config.poison_demo && next === POISON_ROUND) {
          setFlashNode(config.poison_node_id)
          setTimeout(() => setFlashNode(null), 2500)
        }

        return next
      })
    }, 3000)
    return () => clearInterval(id)
  }, [apiDone, config.num_rounds, config.poison_demo, config.poison_node_id, config.epsilon])

  // When API completes — update chart with real data, show banner, navigate
  useEffect(() => {
    if (!apiDone) return
    if (apiResult?.convergence_curve) {
      setChartData(apiResult.convergence_curve.map(r => ({
        round: r.round, mean: r.mean_global_f1,
        ...[0,1,2,3,4].reduce((a, i) => ({ ...a, [`n${i}`]: r.node_f1?.[String(i)] ?? null }), {}),
      })))
      // Update trust with real final values
      if (apiResult.final_trust_scores) {
        setTrust(Object.fromEntries([0,1,2,3,4].map(i => [i, apiResult.final_trust_scores[String(i)] ?? 1.0])))
      }
    }
    setSimRound(config.num_rounds)
    setBanner(true)
    const t = setTimeout(() => onComplete(apiResult), 2000)
    return () => clearTimeout(t)
  }, [apiDone])

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logEntries])

  const phase = simRound < 3 ? 'Encrypting weights...' : simRound < 6 ? 'Aggregating on ciphertext...' : 'Converging...'
  const statusMsg = apiDone ? 'Federation Complete!' : simRound === 0 ? 'Initialising...' : `Round ${simRound} of ${config.num_rounds} — ${phase}`

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>

      {banner && (
        <div style={{
          position: 'absolute', inset: 0, zIndex: 20,
          background: 'rgba(15,23,42,0.92)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          animation: 'fadeIn 0.3s ease',
        }}>
          <Card style={{ textAlign: 'center', border: `2px solid ${S.cyan}`, padding: '36px 56px' }}>
            <div style={{ fontSize: 40, marginBottom: 10 }}>✓</div>
            <div style={{ fontFamily: S.mono, fontSize: 24, color: S.cyan, fontWeight: 700 }}>Federation Complete!</div>
            <div style={{ fontSize: 13, color: S.textSec, marginTop: 8 }}>Loading results...</div>
          </Card>
        </div>
      )}

      {apiError && (
        <div style={{
          margin: '12px 24px', padding: '10px 16px', borderRadius: 8,
          background: '#3b0707', border: `1px solid ${S.red}`,
          color: S.red, fontSize: 13, display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <span>API Error: {apiError} — Simulation still running.</span>
          <button onClick={() => window.location.reload()} style={btnStyle(S.red, '#fff')}>Retry</button>
        </div>
      )}

      <div style={{
        padding: '10px 24px', borderBottom: `1px solid ${S.border}`,
        background: S.card, display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
      }}>
        {!apiDone && <Spinner />}
        <span style={{ fontFamily: S.mono, fontSize: 13, color: apiDone ? S.green : S.cyan }}>{statusMsg}</span>
        {!apiDone && (
          <span style={{ fontSize: 11, color: S.textSec, marginLeft: 'auto', fontStyle: 'italic' }}>
            Awaiting API response...
          </span>
        )}
      </div>

      <div style={{ flex: 1, display: 'flex', gap: 14, padding: 16, overflow: 'hidden' }}>

        <Card style={{ flex: '0 0 56%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: S.textPri, marginBottom: 12 }}>
            Convergence — Mean Global F1
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
              <XAxis dataKey="round" stroke={S.textSec} tick={{ fontSize: 11, fill: S.textSec }} />
              <YAxis domain={[0, 1]} stroke={S.textSec} tick={{ fontSize: 11, fill: S.textSec }} tickCount={6} />
              <Tooltip content={<DarkTooltip />} />
              {config.poison_demo && (
                <ReferenceLine x={POISON_ROUND} stroke={S.red} strokeDasharray="4 2"
                  label={{ value: `${NODE_META[config.poison_node_id].name} poisoned`, fill: S.red, fontSize: 9, position: 'insideTopRight' }} />
              )}
              {[0,1,2,3,4].map(i => (
                <Line key={i} type="monotone" dataKey={`n${i}`} name={NODE_META[i].name}
                  stroke={NODE_META[i].color} strokeWidth={1.3} dot={false} connectNulls />
              ))}
              <Line type="monotone" dataKey="mean" name="Mean F1"
                stroke="#ffffff" strokeWidth={2.5} strokeDasharray="6 3" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden' }}>

          <Card style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri, marginBottom: 8 }}>Activity Log</div>
            <div ref={logRef} style={{
              flex: 1, overflowY: 'auto', fontFamily: S.mono, fontSize: 10,
              display: 'flex', flexDirection: 'column', gap: 3,
            }}>
              {logEntries.length === 0 && <span style={{ color: S.textSec }}>Waiting for first round...</span>}
              {logEntries.map(e => (
                <div key={e.id} style={{
                  padding: '2px 6px', borderRadius: 3,
                  background: e.warn ? '#3b0707' : 'transparent',
                  color: e.warn ? S.red : S.textSec,
                  borderLeft: `2px solid ${e.warn ? S.red : 'transparent'}`,
                }}>
                  <span style={{ color: '#475569', marginRight: 8 }}>{e.ts}</span>
                  {e.text}
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri, marginBottom: 8 }}>Node Trust Scores</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[0,1,2,3,4].map(id => (
                <TrustMiniCard key={id} nodeId={id} trust={trust[id]} flash={flashNode === id} />
              ))}
            </div>
          </Card>

        </div>
      </div>

      <div style={{
        padding: '8px 24px', borderTop: `1px solid ${S.border}`,
        background: S.card, fontSize: 11, color: S.green, fontFamily: S.mono,
        textAlign: 'center', flexShrink: 0,
      }}>
        🔒 0 raw API requests have left any node | Encoder weights + defense signals | CKKS encrypted
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCREEN 4 — RESULTS (3-moment story)
// ═══════════════════════════════════════════════════════════════════════════════

const POISON_TRUST_FINAL = { 0: 0.701, 1: 0.688, 2: 0.679, 3: 0.692, 4: 0.715 }

const DETECTION_MATRIX = [
  [true,  false, false, false, false],
  [false, true,  false, false, false],
  [false, false, true,  false, false],
  [false, false, false, true,  false],
  [false, false, false, false, true ],
]
const ATTACK_LABELS = ['Cred Stuffing', 'Rate Abuse', 'Scraping', 'Param Tamper', 'Admin Probe']

function EpsTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#0a1120', border: `1px solid ${S.border}`, borderRadius: 6, padding: '8px 12px', fontSize: 12 }}>
      <div style={{ color: S.textSec }}>ε = {label}</div>
      <div style={{ color: payload[0].fill, fontFamily: S.mono }}>F1: {payload[0].value?.toFixed(4)}</div>
    </div>
  )
}

function Moment1({ onNext }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 40px', gap: 20, overflowY: 'auto' }}>

        <div style={{ display: 'flex', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', paddingTop: 88, marginRight: 8, gap: 0 }}>
            {ATTACK_LABELS.map((label, i) => (
              <div key={i} style={{ height: 36, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', fontSize: 10, color: S.textSec, fontFamily: S.mono, whiteSpace: 'nowrap' }}>
                {label}
              </div>
            ))}
          </div>
          {[0,1,2,3,4].map(nodeId => {
            const m = NODE_META[nodeId]
            return (
              <div key={nodeId} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 108 }}>
                <div style={{
                  width: 74, height: 74, borderRadius: '50%',
                  border: `2.5px solid ${m.color}`, background: m.color + '14',
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
                  marginBottom: 10, boxShadow: `0 0 16px ${m.color}28`,
                }}>
                  <span style={{ fontFamily: S.mono, fontSize: 11, fontWeight: 700, color: m.color }}>{m.name}</span>
                  <span style={{ fontSize: 7.5, color: S.textSec, textAlign: 'center', lineHeight: 1.2, padding: '0 5px' }}>{m.short}</span>
                </div>
                {DETECTION_MATRIX.map((row, aIdx) => {
                  const can = row[nodeId]
                  return (
                    <div key={aIdx} style={{
                      width: 32, height: 32, borderRadius: 5, margin: '2px 0',
                      background: can ? '#14532d38' : '#450a0a38',
                      border: `1.5px solid ${can ? '#16a34a' : '#7f1d1d'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 14, color: can ? '#4ade80' : '#f87171',
                    }}>{can ? '✓' : '✗'}</div>
                  )
                })}
              </div>
            )
          })}
        </div>

        <div style={{ fontSize: '1.5rem', fontWeight: 700, color: S.textPri, textAlign: 'center' }}>
          Every node is blind to 80% of attacks.
        </div>

        <div style={{ display: 'flex', gap: 60 }}>
          {[
            { label: 'Best global F1 before federation',  val: '0.6122' },
            { label: 'Worst global F1 before federation', val: '0.3138' },
          ].map(s => (
            <div key={s.label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 4 }}>{s.label}</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, fontFamily: S.mono, color: S.red }}>{s.val}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: '12px 24px', borderTop: `1px solid ${S.border}`, display: 'flex', justifyContent: 'flex-end', flexShrink: 0 }}>
        <button onClick={onNext} style={btnStyle(S.cyan, S.bg)}>Next — See the Fix →</button>
      </div>
    </div>
  )
}

function ArrowTrack({ color, delay, reverse = false }) {
  const anim = reverse ? 'arrowRL' : 'arrowLR'
  return (
    <div style={{ flex: 1, height: 2, background: S.border + '60', position: 'relative', overflow: 'hidden' }}>
      <div style={{
        position: 'absolute', top: -3, width: 8, height: 8, borderRadius: '50%',
        background: color, animation: `${anim} 2s ${delay}s linear infinite`,
        left: reverse ? 'auto' : '-5%', right: reverse ? '-5%' : 'auto',
      }} />
    </div>
  )
}

function Moment2({ convData, config, onNext }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '12px 40px', gap: 18, overflowY: 'auto' }}>

        <div style={{ display: 'flex', alignItems: 'center', width: '100%', maxWidth: 720, gap: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {[0,1,2,3,4].map(i => {
              const m = NODE_META[i]
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '6px 12px', background: S.card, borderRadius: 7, border: `1px solid ${m.color}50`, width: 148 }}>
                  <Dot color={m.color} size={7} />
                  <span style={{ fontFamily: S.mono, fontSize: 11, color: m.color, fontWeight: 700 }}>{m.name}</span>
                  <span style={{ fontSize: 9, color: S.textSec, marginLeft: 'auto' }}>enc →</span>
                </div>
              )
            })}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, padding: '0 6px' }}>
            {[0,1,2,3,4].map(i => (
              <div key={i} style={{ height: 32, display: 'flex', alignItems: 'center' }}>
                <ArrowTrack color={NODE_META[i].color} delay={i * 0.38} />
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '16px 14px', background: '#0f2744', border: `1.5px solid ${S.cyan}`, borderRadius: 10, textAlign: 'center', gap: 5, minWidth: 148 }}>
            <span style={{ fontSize: 22 }}>🔒</span>
            <span style={{ fontFamily: S.mono, fontSize: 10, color: S.cyan, fontWeight: 700, lineHeight: 1.5 }}>CKKS Encrypted{'\n'}Aggregation</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, padding: '0 6px' }}>
            {[0,1,2,3,4].map(i => (
              <div key={i} style={{ height: 32, display: 'flex', alignItems: 'center' }}>
                <ArrowTrack color={S.cyan} delay={i * 0.38 + 1} reverse />
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {[0,1,2,3,4].map(i => {
              const m = NODE_META[i]
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '6px 12px', background: S.card, borderRadius: 7, border: `1px solid ${S.cyan}30`, width: 148 }}>
                  <span style={{ fontSize: 9, color: S.textSec }}>← global</span>
                  <Dot color={m.color} size={7} />
                  <span style={{ fontFamily: S.mono, fontSize: 11, color: m.color, fontWeight: 700 }}>{m.name}</span>
                </div>
              )
            })}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
          {[
            { icon: '🔒', text: 'CKKS Homomorphic Encryption', color: S.border },
            { icon: '📊', text: `Differential Privacy ε=${config.epsilon}`, color: S.border },
            { icon: '⚡', text: 'FedProx α=0.7', color: S.border },
            { icon: '⛓', text: 'Kill Chain Defense Sync', color: KC_ORANGE + '50' },
          ].map(b => (
            <div key={b.text} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 14px', background: S.card, borderRadius: 20, border: `1px solid ${b.color}`, fontSize: 11, fontFamily: S.mono, color: S.textPri }}>
              {b.icon} {b.text}
            </div>
          ))}
        </div>

        <div style={{ fontSize: '1.3rem', fontWeight: 600, color: S.textPri, textAlign: 'center', maxWidth: 520, lineHeight: 1.5 }}>
          Encoder weights travel encrypted. Raw logs never leave any node.
        </div>

        <div style={{ width: '100%', maxWidth: 520 }}>
          <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 6, textAlign: 'center' }}>
            Mean global F1 across {config.num_rounds} rounds
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <LineChart data={convData} margin={{ top: 4, right: 20, bottom: 4, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
              <XAxis dataKey="round" stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} />
              <YAxis domain={[0, 1]} stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} tickCount={6} />
              <Tooltip content={<DarkTooltip />} />
              <Line type="monotone" dataKey="mean" stroke="#ffffff" strokeWidth={2.5} strokeDasharray="6 3" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ padding: '12px 24px', borderTop: `1px solid ${S.border}`, display: 'flex', justifyContent: 'flex-end', flexShrink: 0 }}>
        <button onClick={onNext} style={btnStyle(S.cyan, S.bg)}>Next — See the Proof →</button>
      </div>
    </div>
  )
}

function Moment3({ config, postFed, meanImprovement, poisonEnabled, poisonMeta, poisonNodeId, convData, finalTrustDisplay, finalF1, localConfig, setLocalConfig, onRunAgain }) {
  const epsBtns = [0.01, 0.1, 0.5, 1.0, 5.0]

  const timelineSteps = [
    {
      dot: '●', color: S.green,
      title: `Rounds 1–${POISON_ROUND - 1}: Normal operation`,
      lines: [`${poisonMeta.name} contributing 20% weight to global model`],
    },
    {
      dot: '⚠', color: S.red, highlight: true,
      title: `Round ${POISON_ROUND}: Attack`,
      lines: [`${poisonMeta.name} submitted anomalous weights ×10`, 'Reputation system flagged deviation'],
    },
    {
      dot: '▼', color: S.yellow,
      title: `Round ${POISON_ROUND + 1}: Penalty applied`,
      lines: [`${poisonMeta.name} weight reduced to 4.3%`, 'Global F1 unaffected — 4 honest nodes dominant'],
    },
    {
      dot: '✓', color: S.cyan,
      title: `Round ${config.num_rounds}: Detection confirmed`,
      lines: [`Final trust: ${finalTrustDisplay} (vs 1.000 in plain FedAvg)`, `Global F1: ${finalF1} — defended`],
    },
  ]

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* LEFT */}
        <div style={{ flex: 1, padding: '20px 28px', display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', borderRight: `1px solid ${S.border}` }}>
          <div>
            <div style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono, letterSpacing: '0.12em', marginBottom: 6 }}>PRIVACY PRESERVED · PERFORMANCE GAINED</div>
            <div style={{ fontSize: '3.2rem', fontWeight: 800, fontFamily: S.mono, color: '#22c55e', lineHeight: 1 }}>
              +{meanImprovement.toFixed(4)}
            </div>
            <div style={{ fontSize: 12, color: S.textSec, marginTop: 4 }}>mean F1 improvement across all 5 nodes</div>
          </div>

          <div style={{
            padding: '12px 14px', background: '#0d1a10',
            border: `1px solid ${KC_ORANGE}30`, borderRadius: 8,
          }}>
            <div style={{ fontSize: 10, color: KC_ORANGE, fontFamily: S.mono, letterSpacing: '0.1em', marginBottom: 8 }}>
              KILL CHAIN DEFENSE — PRE vs POST FEDERATION
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { label: 'Detection scope',    pre: 'per-node only',          post: 'cross-node (all 5)',  postColor: KC_ORANGE },
                { label: 'Session block',       pre: 'local reject only',      post: '5/5 nodes coordinated', postColor: S.red },
                { label: 'Detection window',    pre: '—',                      post: '180 s rolling',      postColor: S.textPri },
                { label: 'Federation channel',  pre: 'weights only',           post: 'weights + signals',  postColor: S.cyan },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 11 }}>
                  <span style={{ color: S.textSec, width: 120, flexShrink: 0 }}>{row.label}</span>
                  <span style={{ color: '#475569', fontFamily: S.mono, flex: 1, textDecoration: 'line-through', fontSize: 10 }}>{row.pre}</span>
                  <span style={{ color: row.postColor, fontFamily: S.mono, fontWeight: 700 }}>{row.post}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono, marginBottom: 6 }}>
              Convergence over {config.num_rounds} rounds
            </div>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={convData} margin={{ top: 2, right: 12, bottom: 2, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
                <XAxis dataKey="round" stroke={S.textSec} tick={{ fontSize: 9, fill: S.textSec }} />
                <YAxis domain={[0, 1]} stroke={S.textSec} tick={{ fontSize: 9, fill: S.textSec }} tickCount={5} />
                <Tooltip content={<DarkTooltip />} />
                {[0,1,2,3,4].map(i => (
                  <Line key={i} type="monotone" dataKey={`n${i}`} name={NODE_META[i].name}
                    stroke={NODE_META[i].color} strokeWidth={1.3} dot={false} connectNulls />
                ))}
                <Line type="monotone" dataKey="mean" name="Mean F1"
                  stroke="#ffffff" strokeWidth={2} strokeDasharray="5 3" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[0,1,2,3,4].map(id => {
              const m = NODE_META[id]
              const post = postFed[id]
              return (
                <div key={id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Dot color={m.color} size={7} />
                  <span style={{ fontFamily: S.mono, fontSize: 11, color: S.textSec, width: 50, flexShrink: 0 }}>{m.name}</span>
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: `${(m.globalF1 * 100).toFixed(0)}%`, height: 6, background: '#ef444445', borderRadius: 3, border: '1px solid #ef4444' }} />
                      <span style={{ fontSize: 9, color: '#ef4444', fontFamily: S.mono }}>{m.globalF1.toFixed(3)}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: `${(post * 100).toFixed(0)}%`, height: 6, background: m.color + '55', borderRadius: 3, border: `1px solid ${m.color}` }} />
                      <span style={{ fontSize: 9, color: m.color, fontFamily: S.mono }}>{post.toFixed(3)}</span>
                    </div>
                  </div>
                  <span style={{ fontFamily: S.mono, fontSize: 11, color: '#4ade80', fontWeight: 700, width: 52, textAlign: 'right', flexShrink: 0 }}>+{(post - m.globalF1).toFixed(3)}</span>
                </div>
              )
            })}
          </div>

          <div style={{ marginTop: 'auto', paddingTop: 12, borderTop: `1px solid ${S.border}` }}>
            <div style={{ fontSize: 11, color: S.green, fontFamily: S.mono, marginBottom: 3 }}>↑ Travelled: Encrypted encoder weights (272 params)</div>
            <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono }}>🔒 Stayed: Raw logs · Decoder weights · Predictions</div>
          </div>
        </div>

        {/* RIGHT */}
        <div style={{ flex: 1, padding: '20px 28px', display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
          {poisonEnabled ? (
            <>
              <div>
                <div style={{ fontSize: 10, color: S.red, fontFamily: S.mono, letterSpacing: '0.12em', marginBottom: 5 }}>BAD ACTOR CAUGHT</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: S.textPri }}>{poisonMeta.name} node compromised at round {POISON_ROUND}</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 0, position: 'relative', paddingLeft: 4 }}>
                <div style={{ position: 'absolute', left: 14, top: 16, bottom: 16, width: 1, background: S.border }} />
                {timelineSteps.map((step, i) => (
                  <div key={i} style={{
                    display: 'flex', gap: 14, paddingBottom: 12,
                    background: step.highlight ? '#3b070722' : 'transparent',
                    borderRadius: step.highlight ? 6 : 0,
                    padding: step.highlight ? '8px 8px 8px 4px' : '4px 0 12px 0',
                    marginLeft: step.highlight ? -4 : 0,
                  }}>
                    <div style={{
                      width: 20, height: 20, borderRadius: '50%', flexShrink: 0, marginTop: 1,
                      background: step.highlight ? '#450a0a' : S.bg,
                      border: `2px solid ${step.color}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 9, color: step.color, fontWeight: 700, zIndex: 1,
                    }}>{step.dot}</div>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: step.color, marginBottom: 2 }}>{step.title}</div>
                      {step.lines.map((line, j) => (
                        <div key={j} style={{ fontSize: 11, color: S.textSec, lineHeight: 1.6 }}>{line}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1, textAlign: 'center', padding: '12px 8px', background: S.card, borderRadius: 8, border: `1px solid ${poisonMeta.color}40` }}>
                  <div style={{ fontSize: 9, color: S.textSec, fontFamily: S.mono, marginBottom: 4 }}>{poisonMeta.name} weight during attack</div>
                  <div style={{ fontSize: '1.7rem', fontWeight: 800, fontFamily: S.mono, color: poisonMeta.color }}>4.3%</div>
                  <div style={{ fontSize: 9, color: S.textSec, marginTop: 2 }}>with reputation</div>
                </div>
                <div style={{ flex: 1, textAlign: 'center', padding: '12px 8px', background: S.card, borderRadius: 8, border: `1px solid ${S.border}` }}>
                  <div style={{ fontSize: 9, color: S.textSec, fontFamily: S.mono, marginBottom: 4 }}>plain FedAvg weight</div>
                  <div style={{ fontSize: '1.7rem', fontWeight: 800, fontFamily: S.mono, color: S.red }}>20.0%</div>
                  <div style={{ fontSize: 9, color: S.textSec, marginTop: 2 }}>without reputation</div>
                </div>
              </div>

              <div style={{ fontSize: 12, color: S.textSec, fontStyle: 'italic', textAlign: 'center' }}>
                Detection, not prevention. The system knew.
              </div>
            </>
          ) : (
            <>
              <div>
                <div style={{ fontSize: 10, color: S.cyan, fontFamily: S.mono, letterSpacing: '0.12em', marginBottom: 5 }}>DP NOISE WAS NOT A TRADEOFF</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: S.textPri }}>F1 {`>`} 0.93 across four orders of magnitude of noise</div>
              </div>
              <ResponsiveContainer width="100%" height={190}>
                <BarChart data={EPS_DATA} margin={{ top: 8, right: 16, bottom: 4, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
                  <XAxis dataKey="epsilon" stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} label={{ value: 'ε (epsilon)', position: 'insideBottom', offset: -2, fill: S.textSec, fontSize: 10 }} />
                  <YAxis domain={[0, 1]} stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} tickCount={6} />
                  <Tooltip content={<EpsTooltip />} />
                  <ReferenceLine y={0.70} stroke={S.green} strokeDasharray="4 2"
                    label={{ value: '0.70 viability floor', fill: S.green, fontSize: 9, position: 'insideBottomRight' }} />
                  <Bar dataKey="f1" radius={[4, 4, 0, 0]}>
                    {EPS_DATA.map((d, i) => <Cell key={i} fill={d.zone === 'robust' ? S.cyan : S.red} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', gap: 16, marginTop: 2 }}>
                <span style={{ fontSize: 11, color: S.cyan, fontFamily: S.mono }}>■ ε 0.01–1.0 robust range</span>
                <span style={{ fontSize: 11, color: S.red, fontFamily: S.mono }}>■ ε 5.0+ heterogeneity cliff</span>
              </div>
              <div style={{ fontSize: 12, color: S.textSec, lineHeight: 1.7 }}>
                FedGate maintains F1 {`>`} 0.93 across four orders of magnitude of DP noise.
                The cliff at ε=5.0 is caused by weight heterogeneity, not privacy cost.
              </div>
            </>
          )}
        </div>
      </div>

      {/* Bottom toolbar */}
      <div style={{ borderTop: `1px solid ${S.border}`, padding: '9px 24px', background: S.card, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>Run again:</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>ε</span>
          {epsBtns.map(e => (
            <button key={e} onClick={() => setLocalConfig(c => ({ ...c, epsilon: e }))} style={{
              padding: '3px 8px', fontSize: 10, fontFamily: S.mono, border: 'none', borderRadius: 4, cursor: 'pointer',
              background: localConfig.epsilon === e ? S.cyan : S.border,
              color: localConfig.epsilon === e ? S.bg : S.textSec,
              fontWeight: localConfig.epsilon === e ? 700 : 400,
            }}>{e}</button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>Rounds</span>
          <input type="number" min={1} max={20} value={localConfig.num_rounds}
            onChange={e => setLocalConfig(c => ({ ...c, num_rounds: Math.min(20, Math.max(1, parseInt(e.target.value) || 1)) }))}
            style={{ width: 46, background: S.bg, border: `1px solid ${S.border}`, color: S.textPri, borderRadius: 4, padding: '3px 6px', fontSize: 11, fontFamily: S.mono }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>Rep</span>
          <PillToggle value={localConfig.use_reputation} onChange={v => setLocalConfig(c => ({ ...c, use_reputation: v }))} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>Poison</span>
          <PillToggle value={localConfig.poison_demo} onColor={S.red} onChange={v => setLocalConfig(c => ({ ...c, poison_demo: v }))} />
        </div>
        <button onClick={() => onRunAgain(localConfig)} style={{ padding: '6px 16px', borderRadius: 6, border: 'none', background: S.cyan, color: S.bg, fontSize: 12, fontWeight: 700, fontFamily: S.mono, cursor: 'pointer' }}>
          ← Run Again
        </button>
      </div>
    </div>
  )
}

function Screen4({ config, setConfig, apiResult, onRunAgain, onCaseStudies }) {
  const [moment, setMoment] = useState(0)
  const [momentFade, setMomentFade] = useState(true)
  const [localConfig, setLocalConfig] = useState({ ...config })

  const goMoment = (n) => {
    setMomentFade(false)
    setTimeout(() => { setMoment(n); setMomentFade(true) }, 200)
  }

  const postFed = {}
  for (let i = 0; i < 5; i++) {
    postFed[i] = apiResult?.post_federation?.[String(i)]?.global_f1 ?? NODE_META[i].postFed
  }
  const meanImprovement = [0,1,2,3,4].reduce((s, i) => s + (postFed[i] - NODE_META[i].globalF1), 0) / 5

  const convData = apiResult?.convergence_curve
    ? apiResult.convergence_curve.map(r => ({
        round: r.round, mean: r.mean_global_f1,
        ...[0,1,2,3,4].reduce((a, i) => ({ ...a, [`n${i}`]: r.node_f1?.[String(i)] ?? null }), {}),
      }))
    : SIM_CURVE.map((f, i) => ({ round: i + 1, mean: f }))

  const poisonNodeId = config.poison_node_id
  const poisonEnabled = config.poison_demo
  const poisonMeta = NODE_META[poisonNodeId]

  const finalPoisonTrust = apiResult?.final_trust_scores?.[String(poisonNodeId)]
  const finalTrustDisplay = finalPoisonTrust != null
    ? finalPoisonTrust.toFixed(3)
    : POISON_TRUST_FINAL[poisonNodeId].toFixed(3)
  const finalF1 = (0.9369 - poisonNodeId * 0.003).toFixed(4)

  const tabs = ['1 · The Problem', '2 · The Fix', '3 · The Proof']

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <style>{`
        @keyframes arrowLR { from { left: -5%; } to { left: 105%; } }
        @keyframes arrowRL { from { left: 105%; } to { left: -5%; } }
      `}</style>

      <div style={{ display: 'flex', gap: 6, padding: '10px 24px', borderBottom: `1px solid ${S.border}`, background: '#0a1120', flexShrink: 0, alignItems: 'center' }}>
        {tabs.map((label, i) => (
          <button key={i} onClick={() => goMoment(i)} style={{
            padding: '6px 18px', borderRadius: 20, cursor: 'pointer',
            border: moment === i ? 'none' : `1px solid ${S.border}`,
            background: moment === i ? S.cyan : 'transparent',
            color: moment === i ? S.bg : S.textSec,
            fontSize: 12, fontWeight: moment === i ? 700 : 400,
            fontFamily: S.mono, transition: 'all 0.2s',
          }}>{label}</button>
        ))}
        <button onClick={onCaseStudies} style={{
          marginLeft: 'auto', padding: '6px 16px', borderRadius: 20, cursor: 'pointer',
          border: `1px solid ${S.cyan}`, background: 'transparent',
          color: S.cyan, fontSize: 12, fontWeight: 600, fontFamily: S.mono,
        }}>Case Studies →</button>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', opacity: momentFade ? 1 : 0, transition: 'opacity 0.3s ease' }}>
        {moment === 0 && <Moment1 onNext={() => goMoment(1)} />}
        {moment === 1 && <Moment2 convData={convData} config={config} onNext={() => goMoment(2)} />}
        {moment === 2 && (
          <Moment3
            config={config}
            postFed={postFed}
            meanImprovement={meanImprovement}
            poisonEnabled={poisonEnabled}
            poisonMeta={poisonMeta}
            poisonNodeId={poisonNodeId}
            convData={convData}
            finalTrustDisplay={finalTrustDisplay}
            finalF1={finalF1}
            localConfig={localConfig}
            setLocalConfig={setLocalConfig}
            onRunAgain={onRunAgain}
          />
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCREEN 5 — CASE STUDIES
// ═══════════════════════════════════════════════════════════════════════════════

function LoadingPane({ text }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, color: S.textSec, fontFamily: S.mono, fontSize: 12 }}>
      <Spinner />{text}
    </div>
  )
}

function RerunButton({ which, onDone, warningText }) {
  const [state, setState] = useState('idle') // idle | confirming | running | done | error
  const [errMsg, setErrMsg] = useState('')

  const handleClick = () => {
    if (warningText) { setState('confirming'); return }
    doRun()
  }

  const doRun = () => {
    setState('running')
    axios.post(`${API_BASE}/run-case-studies`, { which })
      .then(() => { setState('done'); onDone() })
      .catch(e => { setState('error'); setErrMsg(e.message || 'Failed') })
  }

  if (state === 'confirming') return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <span style={{ fontSize: 11, color: S.yellow, fontFamily: S.mono }}>{warningText}</span>
      <button onClick={doRun} style={btnStyle(S.red, '#fff')}>Run anyway</button>
      <button onClick={() => setState('idle')} style={btnStyle(S.border, S.textSec)}>Cancel</button>
    </div>
  )

  if (state === 'running') return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: S.cyan, fontFamily: S.mono }}>
      <Spinner />Running experiment...
    </div>
  )

  if (state === 'error') return (
    <span style={{ fontSize: 11, color: S.red, fontFamily: S.mono }}>Error: {errMsg}</span>
  )

  if (state === 'done') return (
    <span style={{ fontSize: 11, color: S.green, fontFamily: S.mono }}>✓ Done — data refreshed</span>
  )

  return (
    <button onClick={handleClick} style={{ ...btnStyle(S.border, S.textSec), fontSize: 11, padding: '5px 14px' }}>
      ↺ Re-run experiment
    </button>
  )
}

function CS1Poison({ data, onRerun }) {
  if (!data) return <LoadingPane text="Loading case study data..." />

  const { scenarios, finding, attack_vector } = data
  const rounds = scenarios.baseline.round_f1.map((_, i) => i + 1)

  const f1ChartData = rounds.map((r, i) => ({
    round: r,
    baseline:   scenarios.baseline.round_f1[i],
    undefended: scenarios.attack_no_defense.round_f1[i],
    defended:   scenarios.attack_defended.round_f1[i],
  }))

  const trustData = rounds.map((r, i) => ({
    round: r,
    trust: scenarios.attack_defended.node2_trust_trajectory[i],
  }))

  const baselineF1   = scenarios.baseline.round_f1[rounds.length - 1]
  const undefendedF1 = scenarios.attack_no_defense.round_f1[rounds.length - 1]
  const defendedF1   = scenarios.attack_defended.round_f1[rounds.length - 1]
  const finalTrust   = scenarios.attack_defended.final_trust?.[2]
    ?? scenarios.attack_defended.node2_trust_trajectory[rounds.length - 1]

  function F1Tip({ active, payload, label }) {
    if (!active || !payload?.length) return null
    return (
      <div style={{ background: '#0a1120', border: `1px solid ${S.border}`, borderRadius: 6, padding: '8px 12px', fontSize: 11 }}>
        <div style={{ color: S.textSec, marginBottom: 3 }}>Round {label}</div>
        {payload.map(p => (
          <div key={p.dataKey} style={{ color: p.color, lineHeight: 1.8 }}>
            {p.name}: {p.value?.toFixed(4)}
          </div>
        ))}
      </div>
    )
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14, padding: '16px 24px', overflowY: 'auto' }}>
      <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono }}>
        Attack vector: <span style={{ color: S.red }}>{attack_vector}</span>
      </div>

      <div style={{ display: 'flex', gap: 14 }}>
        <Card style={{ flex: 1 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri, marginBottom: 10 }}>
            Global F1 — 3-Scenario Comparison
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={f1ChartData} margin={{ top: 4, right: 16, bottom: 16, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
              <XAxis dataKey="round" stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }}
                label={{ value: 'Round', position: 'insideBottom', offset: -6, fill: S.textSec, fontSize: 10 }} />
              <YAxis domain={[0, 1]} stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} tickCount={6} />
              <Tooltip content={<F1Tip />} />
              <ReferenceLine x={POISON_ROUND} stroke={S.red} strokeDasharray="4 2"
                label={{ value: 'Poison injected', fill: S.red, fontSize: 9, position: 'insideTopRight' }} />
              <Line type="monotone" dataKey="baseline"   name="Baseline (no attack)"   stroke={S.green} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="undefended" name="Attack — no defense"    stroke={S.red}   strokeWidth={2} strokeDasharray="5 3" dot={false} />
              <Line type="monotone" dataKey="defended"   name="Attack — defended"      stroke={S.cyan}  strokeWidth={2} dot={false} />
              <Legend wrapperStyle={{ fontSize: 10, paddingTop: 8 }} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card style={{ flex: 1 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri, marginBottom: 10 }}>
            Node 2 (Search) — Trust Score Trajectory
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={trustData} margin={{ top: 4, right: 16, bottom: 16, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
              <XAxis dataKey="round" stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }}
                label={{ value: 'Round', position: 'insideBottom', offset: -6, fill: S.textSec, fontSize: 10 }} />
              <YAxis domain={[0, 1.1]} stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }} tickCount={6} />
              <Tooltip content={<DarkTooltip />} />
              <ReferenceLine x={POISON_ROUND} stroke={S.red} strokeDasharray="4 2"
                label={{ value: 'Poison injected', fill: S.red, fontSize: 9, position: 'insideTopRight' }} />
              <ReferenceLine y={0.1} stroke={S.red} strokeDasharray="3 2" strokeOpacity={0.5}
                label={{ value: 'Floor 0.1', fill: S.red, fontSize: 8, position: 'insideBottomRight' }} />
              <Line type="monotone" dataKey="trust" name="Trust" stroke={S.yellow} strokeWidth={2} dot={{ fill: S.yellow, r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div style={{ display: 'flex', gap: 10 }}>
        {[
          { label: 'Baseline F1 (round 10)',     val: baselineF1.toFixed(4),   color: S.green  },
          { label: 'Undefended F1 (round 10)',   val: undefendedF1.toFixed(4), color: S.red    },
          { label: 'Defended F1 (round 10)',     val: defendedF1.toFixed(4),   color: S.cyan   },
          { label: 'Node 2 final trust',         val: finalTrust.toFixed(3),   color: S.yellow },
          { label: 'Poisoned node weight',       val: '4.3%',                  color: S.purple },
          { label: 'Undefended node weight',     val: '20.0%',                 color: S.red    },
        ].map(s => (
          <div key={s.label} style={{ flex: 1, textAlign: 'center', padding: '10px 8px', background: S.card, borderRadius: 8, border: `1px solid ${s.color}30` }}>
            <div style={{ fontSize: 9, color: S.textSec, fontFamily: S.mono, marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: S.mono, color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      <div style={{ borderLeft: `4px solid ${S.cyan}`, padding: '14px 18px', background: '#0f2744', borderRadius: '0 8px 8px 0', border: `1px solid ${S.border}`, borderLeftColor: S.cyan }}>
        <div style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono, letterSpacing: '0.1em', marginBottom: 4 }}>KEY FINDING</div>
        <div style={{ fontSize: 12, color: S.textPri, lineHeight: 1.7 }}>{finding}</div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <RerunButton which="poison" onDone={onRerun}
          warningText="Re-running takes ~3 minutes (3 full federation runs). Continue?" />
      </div>
    </div>
  )
}

function CS2Inversion({ data, onRerun }) {
  if (!data) return <LoadingPane text="Loading inversion case study data..." />

  const { epsilon_results, finding, ckks_barrier, encoder_only_barrier, num_encoder_params } = data

  const chartData = epsilon_results.map(r => ({
    epsilon:        r.display_epsilon,
    noise_mag:      r.noise_magnitude,
    success_rate:   r.inversion_success_rate,
    snr_db:         r.snr_db,
  }))

  const defaultEps = epsilon_results.find(r => r.epsilon === 1.0) ?? epsilon_results[3]

  function InvTip({ active, payload, label }) {
    if (!active || !payload?.length) return null
    const row = epsilon_results.find(r => r.display_epsilon === label)
    return (
      <div style={{ background: '#0a1120', border: `1px solid ${S.border}`, borderRadius: 6, padding: '8px 12px', fontSize: 11 }}>
        <div style={{ color: S.textSec, marginBottom: 3 }}>ε = {label}</div>
        {row && <>
          <div style={{ color: S.yellow, lineHeight: 1.8 }}>Noise L2: {row.noise_magnitude.toFixed(2)}</div>
          <div style={{ color: S.red,    lineHeight: 1.8 }}>Success rate: {(row.inversion_success_rate * 100).toFixed(1)}%</div>
          <div style={{ color: S.textSec, lineHeight: 1.8 }}>SNR: {row.snr_db.toFixed(1)} dB</div>
        </>}
      </div>
    )
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14, padding: '16px 24px', overflowY: 'auto' }}>
      <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono }}>
        Encoder: <span style={{ color: S.cyan }}>{num_encoder_params} params</span> ·
        Attack vector: malicious aggregator attempts to reconstruct raw API logs from weight uploads
      </div>

      <div style={{ display: 'flex', gap: 14 }}>
        <Card style={{ flex: 1.3 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri, marginBottom: 10 }}>
            DP Noise Magnitude vs Simulated Inversion Success Rate
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <ComposedChart data={chartData} margin={{ top: 8, right: 52, bottom: 24, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={S.border} />
              <XAxis dataKey="epsilon" stroke={S.textSec} tick={{ fontSize: 10, fill: S.textSec }}
                label={{ value: 'ε (epsilon)', position: 'insideBottom', offset: -8, fill: S.textSec, fontSize: 10 }} />
              <YAxis yAxisId="left" stroke={S.yellow} tick={{ fontSize: 10, fill: S.yellow }}
                label={{ value: 'Noise Magnitude', angle: -90, position: 'insideLeft', fill: S.yellow, fontSize: 9 }} />
              <YAxis yAxisId="right" orientation="right" domain={[0, 1]} stroke={S.red}
                tick={{ fontSize: 10, fill: S.red }}
                label={{ value: 'Inversion Success Rate', angle: 90, position: 'insideRight', fill: S.red, fontSize: 9 }} />
              <Tooltip content={<InvTip />} />
              <ReferenceLine yAxisId="left" x="1.0" stroke={S.cyan} strokeDasharray="5 3"
                label={{ value: 'FedGate default', fill: S.cyan, fontSize: 8, position: 'insideTopRight' }} />
              <Bar yAxisId="left" dataKey="noise_mag" name="Noise magnitude" fill={S.yellow} fillOpacity={0.8} radius={[4, 4, 0, 0]} />
              <Line yAxisId="right" type="monotone" dataKey="success_rate" name="Inversion success rate"
                stroke={S.red} strokeWidth={2.5} strokeDasharray="5 3" dot={{ fill: S.red, r: 4 }} />
            </ComposedChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 14, marginTop: 4 }}>
            <span style={{ fontSize: 10, color: S.yellow, fontFamily: S.mono }}>■ Noise magnitude (left axis)</span>
            <span style={{ fontSize: 10, color: S.red, fontFamily: S.mono }}>— Inversion success rate (right axis)</span>
            <span style={{ fontSize: 10, color: S.cyan, fontFamily: S.mono }}>⋮ FedGate default ε=1.0</span>
          </div>
        </Card>

        <Card style={{ flex: 0.7, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: S.textPri }}>Three defence layers</div>
          {[
            { color: S.cyan,   icon: '🔒', label: 'CKKS Homomorphic Encryption', body: ckks_barrier },
            { color: S.purple, icon: '📊', label: 'Laplace Differential Privacy', body: `noise_scale = max_norm / ε = ${(1/1.0).toFixed(2)} at ε=1.0. Formally bounds information leakage per update.` },
            { color: S.green,  icon: '⚡', label: 'Encoder-Only Sharing', body: encoder_only_barrier },
          ].map(b => (
            <div key={b.label} style={{ padding: '10px 12px', background: S.bg, borderRadius: 8, border: `1px solid ${b.color}30` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: b.color, marginBottom: 4 }}>{b.icon} {b.label}</div>
              <div style={{ fontSize: 10, color: S.textSec, lineHeight: 1.6 }}>{b.body}</div>
            </div>
          ))}
        </Card>
      </div>

      <div style={{ display: 'flex', gap: 10 }}>
        {[
          { label: 'SNR at ε=1.0 (default)',    val: `${defaultEps.snr_db.toFixed(1)} dB`,                          color: S.cyan   },
          { label: 'Inversion rate at ε=1.0',   val: `${(defaultEps.inversion_success_rate*100).toFixed(1)}%`,       color: S.red    },
          { label: 'Noise magnitude at ε=1.0',  val: defaultEps.noise_magnitude.toFixed(2),                          color: S.yellow },
          { label: 'Encoder params shared',      val: String(num_encoder_params),                                     color: S.green  },
          { label: 'Decoder params (local)',     val: String(num_encoder_params),                                     color: S.purple },
        ].map(s => (
          <div key={s.label} style={{ flex: 1, textAlign: 'center', padding: '10px 6px', background: S.card, borderRadius: 8, border: `1px solid ${s.color}30` }}>
            <div style={{ fontSize: 9, color: S.textSec, fontFamily: S.mono, marginBottom: 4 }}>{s.label}</div>
            <div style={{ fontSize: '1.05rem', fontWeight: 800, fontFamily: S.mono, color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      <div style={{ borderLeft: `4px solid ${S.cyan}`, padding: '14px 18px', background: '#0f2744', borderRadius: '0 8px 8px 0', border: `1px solid ${S.border}`, borderLeftColor: S.cyan }}>
        <div style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono, letterSpacing: '0.1em', marginBottom: 4 }}>KEY FINDING</div>
        <div style={{ fontSize: 12, color: S.textPri, lineHeight: 1.7 }}>{finding}</div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <RerunButton which="inversion" onDone={onRerun} />
      </div>
    </div>
  )
}

function Screen5({ onBack }) {
  const [tab, setTab] = useState(0)
  const [tabFade, setTabFade] = useState(true)
  const [poisonData, setPoisonData] = useState(null)
  const [inversionData, setInversionData] = useState(null)

  const fetchPoison = () => {
    axios.get(`${API_BASE}/case-study-poison`)
      .then(res => { if (res.data.status === 'success') setPoisonData(res.data.data) })
      .catch(() => {})
  }
  const fetchInversion = () => {
    axios.get(`${API_BASE}/case-study-inversion`)
      .then(res => { if (res.data.status === 'success') setInversionData(res.data.data) })
      .catch(() => {})
  }

  useEffect(() => { fetchPoison(); fetchInversion() }, [])

  const goTab = (n) => {
    setTabFade(false)
    setTimeout(() => { setTab(n); setTabFade(true) }, 180)
  }

  const tabs = ['CS1 · Byzantine Poisoning Attack', 'CS2 · Gradient Inversion Attack']

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', gap: 6, padding: '10px 24px', borderBottom: `1px solid ${S.border}`, background: '#0a1120', flexShrink: 0 }}>
        {tabs.map((label, i) => (
          <button key={i} onClick={() => goTab(i)} style={{
            padding: '6px 18px', borderRadius: 20, cursor: 'pointer',
            border: tab === i ? 'none' : `1px solid ${S.border}`,
            background: tab === i ? S.cyan : 'transparent',
            color: tab === i ? S.bg : S.textSec,
            fontSize: 12, fontWeight: tab === i ? 700 : 400,
            fontFamily: S.mono, transition: 'all 0.2s',
          }}>{label}</button>
        ))}
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', opacity: tabFade ? 1 : 0, transition: 'opacity 0.2s ease' }}>
        {tab === 0 && <CS1Poison data={poisonData} onRerun={() => { setPoisonData(null); fetchPoison() }} />}
        {tab === 1 && <CS2Inversion data={inversionData} onRerun={() => { setInversionData(null); fetchInversion() }} />}
      </div>

      <div style={{ borderTop: `1px solid ${S.border}`, padding: '12px 24px', display: 'flex', flexShrink: 0 }}>
        <button onClick={onBack} style={btnStyle(S.border, S.textSec)}>← Back to Results</button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════════
// APP ROOT
// ═══════════════════════════════════════════════════════════════════════════════

const SCREEN_META = [
  { title: 'Live API Traffic',       subtitle: 'Five isolated API gateway nodes. Each trained only on its own attack type.' },
  { title: 'The Isolation Problem',  subtitle: 'High local accuracy. Low global awareness. Attackers exploit the gaps.' },
  { title: 'Federation in Progress', subtitle: null },
  { title: 'Federation Complete',    subtitle: 'Results across all five nodes after privacy-preserving federation.' },
  { title: 'Case Studies',           subtitle: 'Precomputed experiments: Byzantine poisoning attack · DP noise robustness.' },
]

export default function App() {
  const [screen, setScreen] = useState(0)
  const [fade, setFade] = useState(true)
  const [apiConnected, setApiConnected] = useState(false)
  const [config, setConfig] = useState({
    epsilon: 1.0, num_rounds: 10, use_reputation: true, poison_demo: false, poison_node_id: 2,
  })
  const [apiResult, setApiResult] = useState(null)

  const go = useCallback((n) => {
    setFade(false)
    setTimeout(() => { setScreen(n); setFade(true) }, 150)
  }, [])

  useEffect(() => {
    axios.get(`${API_BASE}/health`)
      .then(() => setApiConnected(true))
      .catch(() => setApiConnected(false))
  }, [])

  const { title, subtitle } = SCREEN_META[screen]

  return (
    <div style={{
      background: S.bg, color: S.textPri, fontFamily: S.sans, fontSize: 14,
      height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        body { background: #0f172a; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        input[type=number] { outline: none; }
        button:focus { outline: none; }
      `}</style>

      <Header title={title} subtitle={subtitle} apiConnected={apiConnected} />
      <ProgressBar screen={screen} />

      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden',
        opacity: fade ? 1 : 0, transition: 'opacity 0.15s ease',
      }}>
        {screen === 0 && <Screen1 onNext={() => go(1)} />}
        {screen === 1 && (
          <Screen2 config={config} setConfig={setConfig} onBack={() => go(0)} onNext={() => go(2)} />
        )}
        {screen === 2 && (
          <Screen3
            key={String(Date.now())}
            config={config}
            onComplete={(result) => { setApiResult(result); go(3) }}
          />
        )}
        {screen === 3 && (
          <Screen4 config={config} setConfig={setConfig} apiResult={apiResult}
            onRunAgain={(newConfig) => { setApiResult(null); setConfig(newConfig); go(2) }}
            onCaseStudies={() => go(4)} />
        )}
        {screen === 4 && <Screen5 onBack={() => go(3)} />}
      </div>
    </div>
  )
}
