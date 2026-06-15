// =============================================================================
// Incidents Page — List and manage security incidents
// =============================================================================
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { RefreshCw, ExternalLink, Filter } from 'lucide-react'
import { apiFetch } from '../App.jsx'
import { formatDistanceToNow, parseISO } from 'date-fns'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function SeverityBadge({ severity }) {
    return <span className={`badge badge-${severity?.toLowerCase()}`}>{severity}</span>
}
function StatusBadge({ status }) {
    return <span className={`badge badge-${status?.toLowerCase()}`}>{status?.replace('_', ' ')}</span>
}

export default function Incidents() {
    const [incidents, setIncidents] = useState([])
    const [total, setTotal] = useState(0)
    const [loading, setLoading] = useState(true)
    const [filters, setFilters] = useState({ status: '', severity: '', site_id: '' })
    const [page, setPage] = useState(1)
    const navigate = useNavigate()
    const PAGE_SIZE = 25

    const load = async () => {
        setLoading(true)
        const params = new URLSearchParams({ page, page_size: PAGE_SIZE })
        if (filters.status) params.set('status', filters.status)
        if (filters.severity) params.set('severity', filters.severity)
        if (filters.site_id) params.set('site_id', filters.site_id)
        try {
            const data = await apiFetch(`/api/incidents?${params}`)
            setIncidents(data.incidents || [])
            setTotal(data.total || 0)
        } catch (e) { console.error(e) }
        finally { setLoading(false) }
    }

    useEffect(() => { load() }, [filters, page])

    const totalPages = Math.ceil(total / PAGE_SIZE)

    return (
        <div>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Incidents</h1>
                    <p className="page-subtitle">{total.toLocaleString()} total incidents</p>
                </div>
                <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /> Refresh</button>
            </div>

            {/* Filters */}
            <div className="card" style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: 140 }}>
                        <label className="form-label"><Filter size={12} /> Status</label>
                        <select className="input" value={filters.status}
                            onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1) }}>
                            <option value="">All Statuses</option>
                            <option>OPEN</option>
                            <option>ACKNOWLEDGED</option>
                            <option>INVESTIGATING</option>
                            <option>RESOLVED</option>
                            <option>FALSE_POSITIVE</option>
                        </select>
                    </div>
                    <div style={{ flex: 1, minWidth: 140 }}>
                        <label className="form-label">Severity</label>
                        <select className="input" value={filters.severity}
                            onChange={e => { setFilters(f => ({ ...f, severity: e.target.value })); setPage(1) }}>
                            <option value="">All Severities</option>
                            {SEVERITY_ORDER.map(s => <option key={s}>{s}</option>)}
                        </select>
                    </div>
                    <div style={{ flex: 2, minWidth: 200 }}>
                        <label className="form-label">Site ID</label>
                        <input className="input" placeholder="site_042" value={filters.site_id}
                            onChange={e => { setFilters(f => ({ ...f, site_id: e.target.value })); setPage(1) }} />
                    </div>
                </div>
            </div>

            {/* Table */}
            <div className="card">
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Site</th>
                                <th>Source IP</th>
                                <th>Events</th>
                                <th>Status</th>
                                <th>Opened</th>
                                <th>Assigned</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && (
                                <tr><td colSpan={9} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                                    Loading...
                                </td></tr>
                            )}
                            {!loading && incidents.length === 0 && (
                                <tr><td colSpan={9} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                                    No incidents match filters
                                </td></tr>
                            )}
                            {incidents.map(inc => (
                                <tr key={inc.id} style={{ cursor: 'pointer' }}
                                    onClick={() => navigate(`/incidents/${inc.id}`)}>
                                    <td><SeverityBadge severity={inc.severity} /></td>
                                    <td style={{ fontWeight: 500 }}>{inc.attack_type}</td>
                                    <td className="mono">{inc.site_id}</td>
                                    <td className="mono" style={{ color: inc.source_ip ? 'var(--critical)' : 'var(--text-muted)' }}>
                                        {inc.source_ip || 'Multiple'}
                                    </td>
                                    <td className="mono">{inc.event_count?.toLocaleString()}</td>
                                    <td><StatusBadge status={inc.status} /></td>
                                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                        {inc.opened_at ? formatDistanceToNow(parseISO(inc.opened_at), { addSuffix: true }) : '—'}
                                    </td>
                                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                        {inc.assigned_to || <span style={{ color: 'var(--text-muted)' }}>Unassigned</span>}
                                    </td>
                                    <td onClick={e => e.stopPropagation()}>
                                        <button className="btn btn-ghost" style={{ padding: '4px 8px' }}
                                            onClick={() => navigate(`/incidents/${inc.id}`)}>
                                            <ExternalLink size={12} />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
                        <button className="btn btn-ghost" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <span style={{ padding: '8px 12px', fontSize: 13, color: 'var(--text-muted)' }}>
                            Page {page} of {totalPages}
                        </span>
                        <button className="btn btn-ghost" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
            </div>
        </div>
    )
}
