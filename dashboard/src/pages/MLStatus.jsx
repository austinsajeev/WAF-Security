// =============================================================================
// ML Status Page — Isolation Forest Anomaly Detection Health
// No auth required — polls /api/ml/status directly
// =============================================================================
import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, Brain, Activity, Shield, Zap, Clock, Wifi, WifiOff } from 'lucide-react'

const API_BASE = ''  // Uses nginx proxy — no hardcoded URL needed

export default function MLStatus() {
    const [data, setData] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [autoRefresh, setAutoRefresh] = useState(true)
    const [lastRefresh, setLastRefresh] = useState(null)

    const load = useCallback(async () => {
        setLoading(true)
        try {
            const res = await fetch(`${API_BASE}/api/ml/status?_t=${Date.now()}`, { cache: 'no-store' })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const json = await res.json()
            setData(json)
            setError(null)
            setLastRefresh(new Date())
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load() }, [load])

    useEffect(() => {
        if (!autoRefresh) return
        const t = setInterval(load, 30000) // 30s auto-refresh
        return () => clearInterval(t)
    }, [autoRefresh, load])

    // Health status badge styling
    const statusConfig = {
        HEALTHY:     { color: '#10b981', bg: 'rgba(16,185,129,0.12)', icon: '✅', glow: '0 0 20px rgba(16,185,129,0.25)' },
        WARMING_UP:  { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  icon: '🔄', glow: '0 0 20px rgba(234,179,8,0.25)' },
        NOT_TRAINED: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  icon: '❌', glow: '0 0 20px rgba(239,68,68,0.25)' },
        DEGRADED:    { color: '#f97316', bg: 'rgba(249,115,22,0.12)', icon: '⚠️', glow: '0 0 20px rgba(249,115,22,0.25)' },
    }

    if (loading && !data) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', flexDirection: 'column', gap: 16 }}>
            <div className="ml-pulse-ring" />
            <span style={{ color: 'var(--text-muted)', fontSize: 14 }}>Connecting to ML Pipeline...</span>
        </div>
    )

    if (error && !data) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', flexDirection: 'column', gap: 16 }}>
            <WifiOff size={32} style={{ color: 'var(--critical)' }} />
            <span style={{ color: 'var(--critical)', fontSize: 14 }}>Failed to connect: {error}</span>
            <button className="btn btn-primary" onClick={load}>Retry</button>
        </div>
    )

    const sc = statusConfig[data?.status] || statusConfig.NOT_TRAINED
    const model = data?.model || {}
    const training = data?.training_dataset || {}
    const cache = data?.redis_cache || {}
    const outliers = cache.top_outliers || []

    return (
        <div>
            {/* Header */}
            <div className="page-header">
                <div>
                    <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <Brain size={22} style={{ color: 'var(--accent-purple)' }} />
                        ML Anomaly Detection
                    </h1>
                    <p className="page-subtitle">
                        Isolation Forest behavioral analysis — Phase 3 AI Pipeline
                    </p>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <button
                        className={`btn ${autoRefresh ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => setAutoRefresh(!autoRefresh)}
                        style={{ fontSize: 12 }}
                    >
                        {autoRefresh ? <Wifi size={12} /> : <WifiOff size={12} />}
                        {autoRefresh ? 'Live' : 'Paused'}
                    </button>
                    <button className="btn btn-ghost" onClick={load}>
                        <RefreshCw size={14} /> Refresh
                    </button>
                </div>
            </div>

            {/* Hero Status Card */}
            <div className="ml-hero-card" style={{ borderColor: sc.color, boxShadow: sc.glow }}>
                <div className="ml-hero-left">
                    <div className="ml-status-badge" style={{ background: sc.bg, color: sc.color }}>
                        <span style={{ fontSize: 20 }}>{sc.icon}</span>
                        {data?.status}
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginTop: 8 }}>{data?.detail}</p>
                    <div style={{ display: 'flex', gap: 16, marginTop: 16 }}>
                        <div className="ml-hero-pill">
                            <Zap size={12} style={{ color: data?.phase3_boost_active ? '#10b981' : '#ef4444' }} />
                            Phase 3 Boost: {data?.phase3_boost_active ? 'ACTIVE' : 'INACTIVE'}
                        </div>
                        <div className="ml-hero-pill">
                            <Clock size={12} />
                            Retrain: every {model.retrain_interval_minutes || 15}min
                        </div>
                    </div>
                </div>
                <div className="ml-hero-right">
                    <div className="ml-algo-badge">
                        <Activity size={14} style={{ color: 'var(--accent-purple)' }} />
                        {model.algorithm || 'IsolationForest'}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                        Features: {(model.features || []).join(' · ')}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                        Contamination: {((model.contamination || 0.03) * 100).toFixed(1)}%
                    </div>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="stat-grid" style={{ marginTop: 20 }}>
                <div className="stat-card stat-blue">
                    <div className="stat-label">IPs Scored</div>
                    <div className="stat-value">{(model.ips_scored || 0).toLocaleString()}</div>
                    <div className="stat-trend">Last training run</div>
                </div>
                <div className="stat-card stat-critical">
                    <div className="stat-label">Outliers Detected</div>
                    <div className="stat-value">{(model.outliers_detected || 0).toLocaleString()}</div>
                    <div className="stat-trend">{(model.contamination_rate || 0).toFixed(1)}% contamination</div>
                </div>
                <div className="stat-card stat-green">
                    <div className="stat-label">Feature Vectors (48h)</div>
                    <div className="stat-value">{(training.ip_feature_vectors || 0).toLocaleString()}</div>
                    <div className="stat-trend">{training.ips_with_attacks || 0} with attacks ({(training.avg_attack_pct || 0).toFixed(1)}%)</div>
                </div>
                <div className="stat-card" style={{}}>
                    <div className="stat-label">Redis Cache</div>
                    <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{cache.cached_outlier_count || 0}</div>
                    <div className="stat-trend">Cached outlier scores</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">Avg Anomaly Score</div>
                    <div className="stat-value" style={{ color: 'var(--accent-purple)', fontSize: 28 }}>
                        {(model.avg_anomaly_score || 0).toFixed(4)}
                    </div>
                    <div className="stat-trend">Max: {(model.max_anomaly_score || 0).toFixed(4)}</div>
                </div>
            </div>

            {/* Bottom Grid: Outlier Table + Model Info */}
            <div className="dashboard-grid" style={{ marginTop: 16 }}>
                {/* Top Outlier IPs */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-title">
                            <Shield size={14} style={{ verticalAlign: 'middle', marginRight: 6, color: 'var(--critical)' }} />
                            Top Anomalous IPs
                        </span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            Sorted by anomaly score (desc)
                        </span>
                    </div>
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>IP Address</th>
                                    <th>Anomaly Score</th>
                                    <th>Score Bar</th>
                                    <th>Cache TTL</th>
                                </tr>
                            </thead>
                            <tbody>
                                {outliers.length === 0 && (
                                    <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>
                                        No outliers cached — model may be warming up
                                    </td></tr>
                                )}
                                {outliers.map((ip, i) => {
                                    const pct = Math.min((ip.anomaly_score / 1.0) * 100, 100)
                                    const barColor = pct > 70 ? 'var(--critical)' : pct > 50 ? 'var(--high)' : 'var(--medium)'
                                    return (
                                        <tr key={ip.ip}>
                                            <td className="mono" style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                                            <td className="mono" style={{ color: 'var(--critical)', fontWeight: 600 }}>{ip.ip}</td>
                                            <td className="mono" style={{ color: barColor, fontWeight: 600 }}>
                                                {ip.anomaly_score.toFixed(4)}
                                            </td>
                                            <td style={{ width: 160 }}>
                                                <div className="ml-score-bar-track">
                                                    <div
                                                        className="ml-score-bar-fill"
                                                        style={{ width: `${pct}%`, background: barColor }}
                                                    />
                                                </div>
                                            </td>
                                            <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                                {ip.cache_ttl_sec > 0 ? `${Math.floor(ip.cache_ttl_sec / 60)}m ${ip.cache_ttl_sec % 60}s` : 'Expired'}
                                            </td>
                                        </tr>
                                    )
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Model Metadata */}
                <div className="card" style={{ alignSelf: 'start' }}>
                    <div className="card-header">
                        <span className="card-title">
                            <Activity size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                            Model Metadata
                        </span>
                    </div>
                    <div className="ml-meta-grid">
                        {[
                            ['Last Trained', model.last_trained_at
                                ? new Date(model.last_trained_at).toLocaleTimeString('en-US', { hour12: false })
                                : 'Never'],
                            ['Algorithm', model.algorithm || '—'],
                            ['Contamination', `${((model.contamination || 0) * 100).toFixed(1)}%`],
                            ['Retrain Interval', `${model.retrain_interval_minutes || 15} min`],
                            ['IPs Scored', model.ips_scored?.toLocaleString() || '0'],
                            ['Outliers', model.outliers_detected?.toLocaleString() || '0'],
                            ['Feature Vectors', training.ip_feature_vectors?.toLocaleString() || '0'],
                            ['Attack IPs', training.ips_with_attacks?.toLocaleString() || '0'],
                            ['Avg Attack %', `${(training.avg_attack_pct || 0).toFixed(1)}%`],
                            ['Redis Keys', cache.cached_outlier_count?.toLocaleString() || '0'],
                        ].map(([label, value]) => (
                            <div key={label} className="ml-meta-item">
                                <span className="ml-meta-label">{label}</span>
                                <span className="ml-meta-value">{value}</span>
                            </div>
                        ))}
                    </div>

                    {lastRefresh && (
                        <div style={{ marginTop: 16, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                            Last refreshed: {lastRefresh.toLocaleTimeString()}
                            {autoRefresh && ' · Auto-refresh: 30s'}
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}
