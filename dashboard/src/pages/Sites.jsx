// =============================================================================
// Sites Page — Per-site security summary
// =============================================================================
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, RefreshCw } from 'lucide-react'
import { apiFetch } from '../App.jsx'
import { format, parseISO } from 'date-fns'

export default function Sites() {
    const [sites, setSites] = useState([])
    const [loading, setLoading] = useState(true)
    const navigate = useNavigate()

    const load = async () => {
        setLoading(true)
        try {
            const data = await apiFetch('/api/dashboard/sites')
            setSites(data.sites || [])
        } catch (e) { console.error(e) }
        finally { setLoading(false) }
    }
    useEffect(() => { load() }, [])

    // Color the row based on high-severity event count
    const riskColor = (high) => {
        if (high > 100) return 'var(--critical)'
        if (high > 20) return 'var(--high)'
        if (high > 0) return 'var(--medium)'
        return 'var(--accent-green)'
    }

    return (
        <div>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Sites Overview</h1>
                    <p className="page-subtitle">Security status per protected website — last 24h</p>
                </div>
                <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /> Refresh</button>
            </div>

            <div className="card">
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th><Globe size={11} /> Site ID</th>
                                <th>Total Events</th>
                                <th>High/Critical Events</th>
                                <th>Risk Level</th>
                                <th>Last Event</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>Loading...</td></tr>
                            )}
                            {!loading && sites.length === 0 && (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                                    No events in the last 24h — monitoring active
                                </td></tr>
                            )}
                            {sites.map(site => {
                                const risk = site.high_events > 100 ? 'CRITICAL'
                                    : site.high_events > 20 ? 'HIGH'
                                        : site.high_events > 0 ? 'MEDIUM'
                                            : 'CLEAN'
                                return (
                                    <tr key={site.site_id}>
                                        <td className="mono" style={{ fontWeight: 600 }}>{site.site_id}</td>
                                        <td className="mono">{site.total_events?.toLocaleString()}</td>
                                        <td className="mono" style={{ color: riskColor(site.high_events), fontWeight: 600 }}>
                                            {site.high_events?.toLocaleString()}
                                        </td>
                                        <td>
                                            <span className={`badge badge-${risk.toLowerCase()}`}>{risk}</span>
                                        </td>
                                        <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                            {site.last_event ? format(parseISO(site.last_event), 'HH:mm:ss') : '—'}
                                        </td>
                                        <td>
                                            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => navigate(`/incidents?site_id=${site.site_id}`)}>
                                                View Incidents
                                            </button>
                                        </td>
                                    </tr>
                                )
                            })}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
