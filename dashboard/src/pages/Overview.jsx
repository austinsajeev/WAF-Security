// =============================================================================
// Overview Page — Main SOC dashboard with live stats + charts
// =============================================================================
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
    AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts'
import { RefreshCw, AlertTriangle, Shield, ShieldAlert } from 'lucide-react'
import { apiFetch } from '../App.jsx'
import { format, parseISO } from 'date-fns'
import { toast } from 'react-toastify'

const SEVERITY_COLORS = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308',
    LOW: '#3b82f6', INFO: '#6b7280'
}

// Custom tooltip for charts
const ChartTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null
    return (
        <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            padding: '10px 14px', borderRadius: 8, fontSize: 12
        }}>
            <p style={{ color: 'var(--text-muted)', marginBottom: 4 }}>{label}</p>
            {payload.map(p => (
                <p key={p.name} style={{ color: p.color }}>
                    {p.name}: <strong>{p.value?.toLocaleString()}</strong>
                </p>
            ))}
        </div>
    )
}

export default function Overview() {
    const [stats, setStats] = useState(null)
    const [timeline, setTimeline] = useState([])
    const [loading, setLoading] = useState(true)
    const [hours, setHours] = useState(24)
    const [wafMode, setWafMode] = useState('On')
    const [togglingMode, setTogglingMode] = useState(false)
    const navigate = useNavigate()

    const load = async () => {
        setLoading(true)
        try {
            const [s, t, modeRes] = await Promise.all([
                apiFetch(`/api/dashboard/overview?hours=${hours}`),
                apiFetch(`/api/dashboard/timeline?hours=${hours}&interval=1 HOUR`),
                apiFetch('/api/gateway/mode').catch(() => ({ mode: 'On' })),
            ])
            setStats(s)
            setTimeline((t.timeline || []).map(r => ({
                ...r,
                label: format(parseISO(r.bucket), 'HH:mm'),
            })))
            setWafMode(modeRes.mode)
        } catch (e) {
            console.error(e)
        } finally {
            setLoading(false)
        }
    }

    const toggleWafMode = async () => {
        const newMode = wafMode === 'On' ? 'DetectionOnly' : 'On'
        setTogglingMode(true)
        try {
            await apiFetch('/api/gateway/mode', {
                method: 'POST',
                body: JSON.stringify({ mode: newMode })
            })
            setWafMode(newMode)
            toast.success(`WAF mode switched to ${newMode === 'On' ? 'Auto-Block' : 'Detection Only'}`)
        } catch (e) {
            toast.error(e.message || 'Failed to switch WAF mode')
        } finally {
            setTogglingMode(false)
        }
    }

    useEffect(() => { load() }, [hours])

    if (loading && !stats) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300 }}>
            <RefreshCw size={20} className="spin" style={{ color: 'var(--accent-blue)' }} />
        </div>
    )

    const topAttacks = stats?.top_attack_types || []
    const topIPs = stats?.top_attacking_ips || []

    return (
        <div>
            {/* Header */}
            <div className="page-header">
                <div>
                    <h1 className="page-title">Security Overview</h1>
                    <p className="page-subtitle">Real-time threat intelligence across all protected sites</p>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <button 
                        className={`btn ${wafMode === 'On' ? 'btn-primary' : 'btn-danger'}`} 
                        onClick={toggleWafMode}
                        disabled={togglingMode}
                        style={{ fontSize: 12 }}
                    >
                        {togglingMode ? <RefreshCw size={14} className="spin" /> : 
                            wafMode === 'On' ? <Shield size={14} /> : <ShieldAlert size={14} />}
                        {wafMode === 'On' ? 'Auto-Block' : 'Detection Only'}
                    </button>
                    <div style={{ width: 1, height: 24, background: 'var(--border)', margin: '0 4px' }} />
                    <select
                        className="input"
                        style={{ width: 120 }}
                        value={hours}
                        onChange={e => setHours(Number(e.target.value))}
                    >
                        <option value={1}>Last 1h</option>
                        <option value={6}>Last 6h</option>
                        <option value={24}>Last 24h</option>
                        <option value={72}>Last 3d</option>
                        <option value={168}>Last 7d</option>
                    </select>
                    <button className="btn btn-ghost" onClick={load}>
                        <RefreshCw size={14} /> Refresh
                    </button>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="stat-grid">
                <div className="stat-card stat-blue">
                    <div className="stat-label">Total Requests</div>
                    <div className="stat-value">{(stats?.total_requests || 0).toLocaleString()}</div>
                    <div className="stat-trend">Last {hours}h</div>
                </div>
                <div className="stat-card stat-critical">
                    <div className="stat-label">WAF Blocks</div>
                    <div className="stat-value">{(stats?.blocked || 0).toLocaleString()}</div>
                    <div className="stat-trend">
                        {wafMode === 'On' ? '🛡 Auto-blocking active' : 'Detection only — not blocking'}
                    </div>
                </div>
                <div className="stat-card" style={{ borderLeft: `3px solid ${wafMode === 'On' ? 'var(--accent-green, #22c55e)' : 'var(--high)'}` }}>
                    <div className="stat-label">WAF Hits (Detected)</div>
                    <div className="stat-value" style={{ color: wafMode === 'On' ? 'var(--accent-green, #22c55e)' : 'var(--high)' }}>
                        {(stats?.waf_hits || 0).toLocaleString()}
                    </div>
                    <div className="stat-trend" style={{ color: wafMode === 'On' ? 'var(--accent-green, #22c55e)' : 'var(--high)', fontWeight: 600 }}>
                        {wafMode === 'On' ? '✅ Auto-Block ON — enforcing' : '⚠️ DetectionOnly mode active'}
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">Unique Attacker IPs</div>
                    <div className="stat-value" style={{ color: 'var(--accent-purple)' }}>
                        {(stats?.unique_ips || 0).toLocaleString()}
                    </div>
                    <div className="stat-trend">Distinct sources</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">Server Errors (5xx)</div>
                    <div className="stat-value" style={{ color: 'var(--medium)' }}>
                        {(stats?.server_errors || 0).toLocaleString()}
                    </div>
                    <div className="stat-trend">May indicate attacks landing</div>
                </div>
            </div>

            {/* Charts Row 1 */}
            <div className="dashboard-grid">
                {/* Attack Timeline */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Attack Timeline</span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>WAF events per hour</span>
                    </div>
                    <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={timeline}>
                            <defs>
                                <linearGradient id="gCritical" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                            <XAxis dataKey="label" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                            <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                            <Tooltip content={<ChartTooltip />} />
                            <Area type="monotone" dataKey="events" name="Total" stroke="#3b82f6" fill="url(#gTotal)" strokeWidth={2} />
                            <Area type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" fill="url(#gCritical)" strokeWidth={2} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                {/* Top Attack Types */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">Attack Types</span>
                    </div>
                    <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={topAttacks} layout="vertical" margin={{ left: 10 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                            <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                            <YAxis dataKey="rule_tag" type="category" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} width={100} />
                            <Tooltip content={<ChartTooltip />} />
                            <Bar dataKey="cnt" name="Events" fill="var(--accent-blue)" radius={[0, 4, 4, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Top Attacking IPs Table */}
            <div className="card">
                <div className="card-header">
                    <span className="card-title">Top Attacking IPs</span>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Last {hours}h</span>
                </div>
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>IP Address</th>
                                <th>Country</th>
                                <th>WAF Hits</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {topIPs.length === 0 && (
                                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No attacking IPs in this window</td></tr>
                            )}
                            {topIPs.map((ip, i) => (
                                <tr key={ip.remote_addr}>
                                    <td className="mono" style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                                    <td className="mono" style={{ color: 'var(--critical)' }}>{ip.remote_addr}</td>
                                    <td>
                                        <span className="badge badge-info">{ip.country_code || '??'}</span>
                                    </td>
                                    <td className="mono" style={{ color: 'var(--high)' }}>{ip.hits?.toLocaleString()}</td>
                                    <td>
                                        <button
                                            className="btn btn-danger"
                                            style={{ padding: '4px 10px', fontSize: 12 }}
                                            onClick={() => navigate('/blocklist')}
                                        >
                                            Block IP
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
