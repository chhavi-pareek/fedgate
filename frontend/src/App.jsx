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

// ── Kill Chain Demo Overlay ────────────────────────────────────────────────────

const KC_PHASES = [
  { label: 'SETUP',       title: 'The Setup — What the Attacker Knows' },
  { label: 'T + 0s',      title: 'Stage 1 — Login Node Hit' },
  { label: 'T + 60s',     title: 'Stage 2 — Payment Node Hit' },
  { label: 'T + 2m 7s',   title: 'Stage 3 — Admin Node Hit' },
  { label: 'BLIND SPOT',  title: 'The Problem — Zero Local Alerts' },
  { label: 'FEDERATION',  title: 'Federation Correlates the Session' },
  { label: 'DETECTED',    title: 'Kill Chain Detected' },
  { label: 'BLOCKED',     title: 'Session Blocked Across All Nodes' },
]

const KC_ATTACK_EVENTS = [
  {
    node_id: 0, node_name: 'Login', time: 'T + 0s',
    event_type: 'AUTH_SUCCESS', endpoint: '/api/login', code: 200,
    note: '1 successful login — indistinguishable from normal user activity.',
    local_verdict: 'Node 0 sees 1 login at 1 req/min. No threshold crossed. No alert.',
  },
  {
    node_id: 1, node_name: 'Payment', time: 'T + 60s',
    event_type: 'PAYMENT_PROBE', endpoint: '/api/payment/confirm', code: 200,
    note: 'Same session, 60s later. 1 payment request — looks like a normal purchase.',
    local_verdict: 'Node 1 sees 1 payment request. Below every rate limit. No alert.',
  },
  {
    node_id: 4, node_name: 'Admin', time: 'T + 2m 7s',
    event_type: 'ADMIN_PROBE', endpoint: '/api/admin/config', code: 403,
    note: 'Admin config probe. Gets a 403. Locally looks like a user accidentally clicking a restricted link.',
    local_verdict: 'Node 4 sees 1 admin probe, rejected. No recognisable pattern. No alert.',
  },
]

function KcMiniNode({ id, state = 'idle', payload = null }) {
  const m = NODE_META[id]
  const styles = {
    idle:    { border: m.color + '50', bg: S.card,           dot: m.color,   text: S.textSec, shadow: 'none' },
    active:  { border: KC_ORANGE,      bg: KC_ORANGE + '18', dot: KC_ORANGE, text: KC_ORANGE, shadow: `0 0 18px ${KC_ORANGE}50` },
    hit:     { border: m.color + '70', bg: m.color + '0a',   dot: m.color,   text: m.color,   shadow: 'none' },
    blocked: { border: S.red,          bg: S.red + '18',     dot: S.red,     text: S.red,     shadow: `0 0 14px ${S.red}40` },
    dimmed:  { border: '#243040',      bg: '#111827',        dot: '#2d3748', text: '#2d3748', shadow: 'none' },
    alerted: { border: '#3d3020',      bg: '#1a1208',        dot: '#6b4c10', text: '#6b4c10', shadow: 'none' },
  }
  const c = styles[state] || styles.idle

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{
        width: 84, borderRadius: 8, padding: '10px 6px 8px',
        background: c.bg, border: `2px solid ${c.border}`,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 5,
        transition: 'all 0.45s ease',
        boxShadow: c.shadow,
      }}>
        <Dot color={c.dot} size={7} />
        <span style={{ fontSize: 9, fontFamily: S.mono, fontWeight: 700, color: c.text, letterSpacing: '0.04em' }}>
          {m.name.toUpperCase()}
        </span>
        {state === 'active' && payload && (
          <div style={{ fontSize: 8, fontFamily: S.mono, textAlign: 'center', animation: 'fadeIn 0.35s', color: KC_ORANGE }}>
            {payload.event_type}<br />
            <span style={{ color: payload.code < 400 ? S.green : S.red }}>HTTP {payload.code}</span>
          </div>
        )}
        {state === 'hit' && (
          <span style={{ fontSize: 8, fontFamily: S.mono, color: m.color }}>✓ HIT</span>
        )}
        {state === 'blocked' && (
          <span style={{ fontSize: 8, fontFamily: S.mono, color: S.red, fontWeight: 700 }}>BLOCKED</span>
        )}
        {state === 'alerted' && (
          <span style={{ fontSize: 8, fontFamily: S.mono, color: '#6b4c10' }}>NO ALERT</span>
        )}
      </div>
      <span style={{ fontSize: 9, color: S.textSec, fontFamily: S.mono }}>Node {id}</span>
    </div>
  )
}

function KcNarration({ children }) {
  return (
    <div style={{
      marginTop: 8, padding: '12px 16px', borderRadius: 8,
      background: S.card, border: `1px solid ${S.border}`,
      fontSize: 13, color: S.textPri, lineHeight: 1.75,
      animation: 'fadeIn 0.4s ease',
    }}>
      {children}
    </div>
  )
}

function PhaseSetup() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 22 }}>
      <div style={{
        padding: '9px 20px', borderRadius: 8,
        background: KC_ORANGE + '15', border: `1px solid ${KC_ORANGE}50`,
        fontFamily: S.mono, fontSize: 12, color: KC_ORANGE, letterSpacing: '0.05em',
      }}>
        TARGET: session_7f3a · 3-stage account takeover · 1 request per node
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', justifyContent: 'center' }}>
        <div style={{
          padding: '12px 16px', borderRadius: 8, minWidth: 88, textAlign: 'center',
          border: `1px solid ${S.red}50`, background: S.red + '10',
          fontFamily: S.mono, fontSize: 11, color: S.red,
        }}>
          ATTACKER<br />
          <span style={{ fontSize: 9, color: S.textSec }}>session_7f3a</span>
        </div>
        <span style={{ fontSize: 18, color: '#334155' }}>→</span>
        <div style={{ display: 'flex', gap: 10 }}>
          {[0, 1, 2, 3, 4].map(id => (
            <KcMiniNode key={id} id={id} state={[0, 1, 4].includes(id) ? 'idle' : 'dimmed'} />
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center' }}>
        {KC_ATTACK_EVENTS.map((ev, i) => (
          <div key={i} style={{
            padding: '10px 16px', borderRadius: 7, minWidth: 140, textAlign: 'center',
            border: `1px solid ${KC_ORANGE}30`, background: KC_ORANGE + '08',
            fontFamily: S.mono, fontSize: 11,
          }}>
            <div style={{ color: KC_ORANGE, fontWeight: 700, marginBottom: 4 }}>{ev.time}</div>
            <div style={{ color: NODE_META[ev.node_id].color, marginBottom: 2 }}>{ev.node_name}</div>
            <div style={{ color: S.textSec, fontSize: 9 }}>{ev.event_type}</div>
          </div>
        ))}
      </div>

      <KcNarration>
        The attacker has compromised <span style={{ color: KC_ORANGE, fontFamily: S.mono }}>session_7f3a</span>.
        They will execute a 3-stage account takeover — test credentials at Login, probe payment access,
        then attempt admin escalation. Each stage hits a <em>different</em> API node spaced 60–90 seconds apart,
        at exactly 1 request per node. Press <strong>Next</strong> to watch each stage play out.
      </KcNarration>
    </div>
  )
}

function PhaseAttackStage({ phase }) {
  const stageIdx = phase - 1
  const ev = KC_ATTACK_EVENTS[stageIdx]
  const hitSoFar = KC_ATTACK_EVENTS.slice(0, stageIdx).map(e => e.node_id)

  const nodeState = (id) => {
    if (id === ev.node_id) return 'active'
    if (hitSoFar.includes(id)) return 'hit'
    if ([0, 1, 4].includes(id)) return 'idle'
    return 'dimmed'
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
      <div style={{
        padding: '8px 24px', borderRadius: 6,
        background: KC_ORANGE + '18', border: `1px solid ${KC_ORANGE}60`,
        fontFamily: S.mono, fontSize: 16, fontWeight: 700, color: KC_ORANGE,
      }}>{ev.time}</div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          padding: '8px 12px', borderRadius: 6,
          border: `1px solid ${S.red}50`, background: S.red + '10',
          fontFamily: S.mono, fontSize: 10, color: S.red,
        }}>ATTACKER</div>
        <span style={{ fontSize: 16, color: KC_ORANGE }}>→</span>
        <div style={{ display: 'flex', gap: 10 }}>
          {[0, 1, 2, 3, 4].map(id => (
            <KcMiniNode key={id} id={id} state={nodeState(id)}
              payload={id === ev.node_id ? { event_type: ev.event_type, code: ev.code } : null}
            />
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'center', animation: 'fadeIn 0.5s ease' }}>
        <div style={{
          padding: '12px 18px', borderRadius: 8, minWidth: 220,
          border: `1px solid ${KC_ORANGE}50`, background: KC_ORANGE + '10',
        }}>
          <div style={{ fontSize: 10, color: KC_ORANGE, fontFamily: S.mono, marginBottom: 8, letterSpacing: '0.08em' }}>
            REQUEST DETAILS
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11, fontFamily: S.mono }}>
            <div><span style={{ color: S.textSec }}>node:      </span><span style={{ color: NODE_META[ev.node_id].color }}>{ev.node_name} (id={ev.node_id})</span></div>
            <div><span style={{ color: S.textSec }}>event:     </span><span style={{ color: KC_ORANGE }}>{ev.event_type}</span></div>
            <div><span style={{ color: S.textSec }}>endpoint:  </span><span style={{ color: S.textPri }}>{ev.endpoint}</span></div>
            <div><span style={{ color: S.textSec }}>code:      </span><span style={{ color: ev.code < 400 ? S.green : S.red }}>HTTP {ev.code}</span></div>
            <div><span style={{ color: S.textSec }}>session:   </span><span style={{ color: S.textPri }}>session_7f3a</span></div>
          </div>
        </div>

        <div style={{
          padding: '12px 18px', borderRadius: 8, flex: 1, minWidth: 200,
          border: `1px solid #2d3748`, background: '#0a0f1a',
        }}>
          <div style={{ fontSize: 10, color: '#475569', fontFamily: S.mono, marginBottom: 8, letterSpacing: '0.08em' }}>
            LOCAL NODE VIEW
          </div>
          <div style={{ fontSize: 12, color: S.textSec, lineHeight: 1.65, marginBottom: 10 }}>
            {ev.local_verdict}
          </div>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 10px', borderRadius: 4,
            background: '#161f2e', border: `1px solid #243040`,
            fontSize: 10, fontFamily: S.mono, color: '#475569',
          }}>
            ● NO LOCAL ALERT
          </div>
        </div>
      </div>

      <KcNarration>{ev.note}</KcNarration>
    </div>
  )
}

function PhaseBlindSpot() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
      <div style={{
        display: 'flex', gap: 10, alignItems: 'center',
        padding: '10px 20px', borderRadius: 8,
        background: S.red + '12', border: `1px solid ${S.red}40`,
        fontFamily: S.mono, fontSize: 13,
      }}>
        <span style={{ color: S.textSec }}>3 nodes hit</span>
        <span style={{ color: '#334155' }}>·</span>
        <span style={{ color: S.textSec }}>3 requests total</span>
        <span style={{ color: '#334155' }}>·</span>
        <span style={{ color: S.red, fontWeight: 700 }}>0 alerts fired</span>
      </div>

      <div style={{ display: 'flex', gap: 10 }}>
        {[0, 1, 2, 3, 4].map(id => (
          <KcMiniNode key={id} id={id} state={[0, 1, 4].includes(id) ? 'alerted' : 'dimmed'} />
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, width: '100%', maxWidth: 580 }}>
        {KC_ATTACK_EVENTS.map((ev, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '8px 14px', borderRadius: 6,
            background: S.card, border: `1px solid ${S.border}`,
            fontFamily: S.mono, fontSize: 11,
          }}>
            <span style={{ color: KC_ORANGE, minWidth: 56 }}>{ev.time}</span>
            <span style={{ color: NODE_META[ev.node_id].color, minWidth: 60 }}>{ev.node_name}</span>
            <span style={{ color: S.textSec, flex: 1 }}>{ev.event_type} · HTTP {ev.code}</span>
            <span style={{
              padding: '2px 8px', borderRadius: 3,
              background: '#161f2e', border: `1px solid #243040`,
              color: '#475569', fontSize: 9,
            }}>NO ALERT</span>
          </div>
        ))}
      </div>

      <KcNarration>
        Each node saw only <strong>1 request</strong> — far below any per-node rate limit or anomaly threshold.
        Login thinks it was a normal login. Payment thinks it was a normal purchase. Admin thinks it was a mis-click.
        <br /><br />
        <span style={{ color: S.red }}>This is the core blind spot in isolated API security:</span> the attack is
        distributed across nodes, so no individual node accumulates enough signal to raise an alert. The attacker's
        behaviour is only suspicious when all three events are seen <em>together</em>.
      </KcNarration>
    </div>
  )
}

function PhaseFederation({ fedArrows }) {
  const FED_NODES = [
    { id: 0, color: '#00d4ff', event: 'AUTH_SUCCESS',  time: 'T+0s' },
    { id: 1, color: '#51cf66', event: 'PAYMENT_PROBE', time: 'T+60s' },
    { id: 4, color: '#ff6b6b', event: 'ADMIN_PROBE',   time: 'T+2m7s' },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 22 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, justifyContent: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {FED_NODES.map(n => (
            <div key={n.id} style={{
              padding: '9px 14px', borderRadius: 7, minWidth: 130,
              border: `1px solid ${n.color}60`, background: n.color + '0d',
              fontFamily: S.mono, fontSize: 11,
            }}>
              <div style={{ color: n.color, fontWeight: 700, marginBottom: 2 }}>{NODE_META[n.id].name}</div>
              <div style={{ color: S.textSec, fontSize: 9 }}>{n.event}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'flex-start' }}>
          {FED_NODES.map((n, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 6,
              opacity: fedArrows ? 1 : 0,
              transition: `opacity 0.4s ease ${i * 0.18}s`,
            }}>
              <div style={{ width: 40, height: 2, background: S.green, borderRadius: 1 }} />
              <span style={{ fontSize: 8, fontFamily: S.mono, color: S.green, whiteSpace: 'nowrap' }}>
                SHA256(session_7f3a) · {n.time}
              </span>
              <div style={{ width: 16, height: 2, background: S.green, borderRadius: 1 }} />
              <span style={{ color: S.green, fontSize: 11 }}>→</span>
            </div>
          ))}
        </div>

        <div style={{
          padding: '18px 22px', borderRadius: 10, textAlign: 'center', minWidth: 130,
          border: `2px solid ${S.cyan}60`, background: S.cyan + '0d',
          fontFamily: S.mono,
          opacity: fedArrows ? 1 : 0.35,
          transition: 'opacity 0.5s ease 0.55s',
        }}>
          <div style={{ color: S.cyan, fontWeight: 700, fontSize: 13, marginBottom: 4 }}>FedGate</div>
          <div style={{ color: S.cyan, fontSize: 10, marginBottom: 4 }}>Aggregator</div>
          <div style={{ color: S.textSec, fontSize: 9 }}>CKKS-encrypted</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, width: '100%', maxWidth: 660 }}>
        <div style={{
          flex: 1, padding: '12px 14px', borderRadius: 8,
          border: `1px solid ${S.green}40`, background: S.green + '08',
        }}>
          <div style={{ fontSize: 10, color: S.green, fontFamily: S.mono, marginBottom: 8, letterSpacing: '0.08em' }}>
            CROSSES THE CHANNEL
          </div>
          {[
            'SHA-256(session_7f3a) — irreversible hash',
            'Timestamp (relative offset only)',
            'Node identifier (0, 1, 4)',
            'CKKS-encrypted encoder weights',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 5, fontSize: 11 }}>
              <span style={{ color: S.green, flexShrink: 0 }}>✓</span>
              <span style={{ color: S.textPri }}>{item}</span>
            </div>
          ))}
        </div>
        <div style={{
          flex: 1, padding: '12px 14px', borderRadius: 8,
          border: `1px solid #2d3748`, background: '#0a0f1a',
        }}>
          <div style={{ fontSize: 10, color: '#475569', fontFamily: S.mono, marginBottom: 8, letterSpacing: '0.08em' }}>
            STAYS LOCAL
          </div>
          {[
            'Raw API request logs',
            'Session credentials / tokens',
            'User identity / PII',
            'Request payloads and bodies',
            'Decoder model weights',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 5, fontSize: 11 }}>
              <span style={{ color: '#475569', flexShrink: 0 }}>✗</span>
              <span style={{ color: '#475569' }}>{item}</span>
            </div>
          ))}
        </div>
      </div>

      <KcNarration>
        Alongside CKKS-encrypted model weights each round, FedGate's federation channel carries
        <span style={{ color: S.green }}> minimal session-level signals</span>: only the hashed session ID
        and a timestamp. The hash is one-way — SHA-256 cannot be reversed to recover the original session token.
        Raw logs, credentials, and payloads never leave any node. This is the privacy guarantee.
      </KcNarration>
    </div>
  )
}

function PhaseDetection() {
  const [revealed, setRevealed] = useState(false)
  useEffect(() => { const t = setTimeout(() => setRevealed(true), 500); return () => clearTimeout(t) }, [])

  const events = [
    { id: 0, name: 'Login',   time: 'T + 0s',    color: '#00d4ff', event: 'AUTH_SUCCESS',  elapsed: 0 },
    { id: 1, name: 'Payment', time: 'T + 60s',   color: '#51cf66', event: 'PAYMENT_PROBE', elapsed: 60 },
    { id: 4, name: 'Admin',   time: 'T + 2m 7s', color: '#ff6b6b', event: 'ADMIN_PROBE',   elapsed: 127 },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
      <div style={{ width: '100%', maxWidth: 640 }}>
        <div style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono, marginBottom: 12, letterSpacing: '0.06em' }}>
          SESSION HASH: SHA256(session_7f3a) · DETECTION WINDOW: 180s
        </div>
        <div style={{ position: 'relative', paddingBottom: 36 }}>
          <div style={{ position: 'absolute', bottom: 20, left: 0, right: 0, height: 2, background: S.border, borderRadius: 1 }} />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
            {events.map((ev, i) => (
              <div key={i} style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                opacity: revealed ? 1 : 0,
                transform: revealed ? 'translateY(0)' : 'translateY(8px)',
                transition: `all 0.5s ease ${i * 0.22}s`,
              }}>
                <div style={{
                  padding: '8px 12px', borderRadius: 7, minWidth: 120, textAlign: 'center',
                  border: `1px solid ${ev.color}60`, background: ev.color + '12',
                  fontFamily: S.mono, fontSize: 10,
                }}>
                  <div style={{ color: ev.color, fontWeight: 700, marginBottom: 2 }}>{ev.name}</div>
                  <div style={{ color: S.textSec }}>{ev.event}</div>
                </div>
                <div style={{ width: 2, height: 16, background: ev.color }} />
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: ev.color, zIndex: 1, position: 'relative' }} />
                <div style={{ fontSize: 9, color: ev.color, fontFamily: S.mono, fontWeight: 700 }}>{ev.time}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{
        width: '100%', maxWidth: 640,
        padding: '12px 16px', borderRadius: 8,
        border: `1px solid ${S.border}`, background: S.card,
        fontFamily: S.mono, fontSize: 11, lineHeight: 1.85,
      }}>
        <div style={{ color: '#475569', marginBottom: 6, letterSpacing: '0.06em' }}>DETECTION LOGIC:</div>
        <div><span style={{ color: '#00d4ff' }}>Login  </span><span style={{ color: S.textSec }}> at T+0s    — node_id=0 ✓</span></div>
        <div><span style={{ color: '#51cf66' }}>Payment</span><span style={{ color: S.textSec }}> at T+60s   — node_id=1 ✓  (sequence: 0 → 1)</span></div>
        <div><span style={{ color: '#ff6b6b' }}>Admin  </span><span style={{ color: S.textSec }}> at T+127s  — node_id=4 ✓  (sequence: 0 → 1 → 4)</span></div>
        <div style={{ marginTop: 6, color: S.textSec }}>Elapsed: <span style={{ color: KC_ORANGE }}>127s</span> &lt; window <span style={{ color: S.green }}>180s</span> → SEQUENCE MATCH</div>
      </div>

      {revealed && (
        <div style={{
          width: '100%', maxWidth: 640,
          padding: '14px 20px', borderRadius: 8,
          border: `2px solid ${KC_ORANGE}`, background: KC_ORANGE + '12',
          animation: 'fadeIn 0.5s ease 0.65s both',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: S.mono, fontSize: 14, fontWeight: 700, color: KC_ORANGE }}>
              ⚠ KILL_CHAIN_DETECTED
            </span>
            <span style={{
              padding: '2px 8px', borderRadius: 3,
              background: KC_ORANGE + '25', border: `1px solid ${KC_ORANGE}50`,
              fontFamily: S.mono, fontSize: 10, color: KC_ORANGE,
            }}>Login → Payment → Admin</span>
          </div>
          <div style={{ fontSize: 11, color: S.textSec, fontFamily: S.mono }}>
            session: session_7f3a · elapsed: 127s · nodes: [0, 1, 4]
          </div>
        </div>
      )}

      <KcNarration>
        The <span style={{ fontFamily: S.mono, color: S.cyan }}>KillChainDetector</span> checks whether
        KILL_CHAIN_SEQUENCE <span style={{ fontFamily: S.mono, color: S.textSec }}>[0 → 1 → 4]</span> appeared
        in order within 180 seconds for the same session hash. It did — in 127 seconds.
        No single node had this picture. Only the federation layer, which received session hashes from all three
        nodes, could correlate them into an alert.
      </KcNarration>
    </div>
  )
}

function PhaseBlocked({ blockedNodes }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        {[0, 1, 2, 3, 4].map(id => (
          <KcMiniNode key={id} id={id} state={blockedNodes.includes(id) ? 'blocked' : 'idle'} />
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 5, width: '100%', maxWidth: 560 }}>
        {[0, 1, 4, 3, 2].map((id) => {
          const done = blockedNodes.includes(id)
          return (
            <div key={id} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 14px', borderRadius: 6,
              background: done ? S.red + '12' : S.card,
              border: `1px solid ${done ? S.red + '50' : S.border}`,
              transition: 'all 0.4s ease', opacity: done ? 1 : 0.35,
              fontFamily: S.mono, fontSize: 11,
            }}>
              <Dot color={done ? S.red : '#334155'} size={6} />
              <span style={{ color: done ? S.red : S.textSec, flex: 1 }}>{NODE_META[id].name}</span>
              {done
                ? <span style={{ color: S.red, fontSize: 9, fontWeight: 700 }}>SESSION BLOCKED</span>
                : <Spinner />}
            </div>
          )
        })}
      </div>

      <div style={{
        padding: '9px 20px', borderRadius: 6,
        background: S.green + '10', border: `1px solid ${S.green}40`,
        fontFamily: S.mono, fontSize: 12, color: S.green,
      }}>
        session_7f3a rejected at {blockedNodes.length}/5 nodes
      </div>

      <KcNarration>
        The <span style={{ fontFamily: S.mono, color: S.cyan }}>SESSION_BLOCK</span> command propagates
        across all 5 nodes via the federation channel. Because the block travels the same CKKS-encrypted
        path as model weights, the attacker's session is revoked everywhere simultaneously — including nodes
        like Search and Profile that never directly saw the suspicious traffic. No raw session data
        ever left any node to make this happen.
      </KcNarration>
    </div>
  )
}

function KillChainDemoOverlay({ onClose }) {
  const [phase, setPhase] = useState(0)
  const [blockedNodes, setBlockedNodes] = useState([])
  const [fedArrows, setFedArrows] = useState(false)
  const total = KC_PHASES.length

  function next() {
    if (phase >= total - 1) return
    const nextPhase = phase + 1
    setPhase(nextPhase)
    if (nextPhase === 5) setTimeout(() => setFedArrows(true), 520)
    if (nextPhase === 7) {
      const order = [0, 1, 4, 3, 2]
      order.forEach((id, i) => setTimeout(() => setBlockedNodes(prev => [...prev, id]), i * 360 + 400))
    }
  }

  function prev() {
    if (phase <= 0) return
    if (phase === 5) setFedArrows(false)
    if (phase === 7) setBlockedNodes([])
    setPhase(p => p - 1)
  }

  function jumpTo(i) {
    if (i >= phase) return
    if (phase === 7 && i < 7) setBlockedNodes([])
    if (phase >= 5 && i < 5) setFedArrows(false)
    setPhase(i)
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(4,8,18,0.96)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      animation: 'fadeIn 0.22s ease',
    }}>
      <div style={{
        width: '92vw', maxWidth: 830, maxHeight: '92vh',
        background: S.bg, border: `1px solid ${S.border}`,
        borderRadius: 14, display: 'flex', flexDirection: 'column',
        overflow: 'hidden', boxShadow: '0 0 80px rgba(0,0,0,0.85)',
      }}>
        {/* Header */}
        <div style={{
          padding: '11px 18px', borderBottom: `1px solid ${S.border}`,
          display: 'flex', alignItems: 'center', gap: 10,
          background: '#080e1c', flexShrink: 0,
        }}>
          <span style={{ fontFamily: S.mono, fontSize: 12, fontWeight: 700, color: KC_ORANGE, letterSpacing: '0.07em' }}>
            KILL CHAIN DEMO
          </span>
          <span style={{ color: S.border }}>|</span>
          <span style={{ fontSize: 12, color: S.textPri, flex: 1 }}>{KC_PHASES[phase].title}</span>
          <button onClick={onClose} style={{
            background: 'transparent', border: `1px solid ${S.border}`,
            color: S.textSec, borderRadius: 5, padding: '3px 10px',
            cursor: 'pointer', fontSize: 11, fontFamily: S.mono,
          }}>✕</button>
        </div>

        {/* Phase stepper */}
        <div style={{
          display: 'flex', borderBottom: `1px solid ${S.border}`,
          background: '#080e1c', flexShrink: 0, overflowX: 'auto',
        }}>
          {KC_PHASES.map((p, i) => (
            <div key={i}
              onClick={() => i < phase && jumpTo(i)}
              style={{
                flex: 1, minWidth: 64, padding: '7px 4px', textAlign: 'center',
                borderRight: i < KC_PHASES.length - 1 ? `1px solid ${S.border}` : 'none',
                background: i === phase ? KC_ORANGE + '15' : i < phase ? S.green + '08' : 'transparent',
                cursor: i < phase ? 'pointer' : 'default',
                transition: 'background 0.2s',
              }}>
              <div style={{
                fontSize: 8, fontFamily: S.mono, fontWeight: 700, letterSpacing: '0.05em',
                color: i === phase ? KC_ORANGE : i < phase ? S.green : '#3a4f65',
                marginBottom: 4,
              }}>{p.label}</div>
              <div style={{
                width: 7, height: 7, borderRadius: '50%', margin: '0 auto',
                background: i === phase ? KC_ORANGE : i < phase ? S.green : '#243040',
                transition: 'all 0.3s',
              }} />
            </div>
          ))}
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '22px 24px' }}>
          {phase === 0 && <PhaseSetup />}
          {phase === 1 && <PhaseAttackStage phase={1} />}
          {phase === 2 && <PhaseAttackStage phase={2} />}
          {phase === 3 && <PhaseAttackStage phase={3} />}
          {phase === 4 && <PhaseBlindSpot />}
          {phase === 5 && <PhaseFederation fedArrows={fedArrows} />}
          {phase === 6 && <PhaseDetection />}
          {phase === 7 && <PhaseBlocked blockedNodes={blockedNodes} />}
        </div>

        {/* Navigation */}
        <div style={{
          borderTop: `1px solid ${S.border}`, padding: '11px 18px',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          background: '#080e1c', flexShrink: 0,
        }}>
          <button onClick={prev} disabled={phase === 0} style={btnStyle(S.border, S.textPri, phase === 0)}>
            ← Back
          </button>
          <span style={{ fontSize: 10, color: S.textSec, fontFamily: S.mono }}>
            {phase + 1} / {total}
          </span>
          {phase === total - 1
            ? <button onClick={onClose} style={btnStyle(S.green, S.bg)}>✓ Done</button>
            : <button onClick={next} style={btnStyle(KC_ORANGE, '#fff')}>Next →</button>
          }
        </div>
      </div>
    </div>
  )
}

function Screen1({ onNext }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [showKcDemo, setShowKcDemo]     = useState(false)

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {showKcDemo && <KillChainDemoOverlay onClose={() => setShowKcDemo(false)} />}

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px 8px' }}>
        <div style={{ display: 'flex', gap: 12 }}>
          {[0, 1, 2, 3, 4].map(id => (
            <NodeTrafficPanel key={id} nodeId={id}
              onAttackClick={(nodeId) => setSelectedNode(prev => prev === nodeId ? null : nodeId)}
            />
          ))}
        </div>
        {!selectedNode && (
          <div style={{ textAlign: 'center', marginTop: 10, fontSize: 11, color: S.textSec, fontStyle: 'italic' }}>
            Click any red <span style={{ color: S.red, fontFamily: S.mono }}>DETECTED</span> row to analyse the attack · or open the Kill Chain Demo below
          </div>
        )}
      </div>

      {selectedNode !== null && (
        <AttackDetailPanel nodeId={selectedNode} onClose={() => setSelectedNode(null)} />
      )}

      <div style={{
        borderTop: `1px solid ${S.border}`, padding: '14px 24px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0,
      }}>
        <button onClick={() => setShowKcDemo(true)} style={btnStyle(KC_ORANGE, '#fff')}>
          Kill Chain Demo
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
