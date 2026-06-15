// =============================================================================
// Incident Detail Page — Full incident view with timeline + actions
// =============================================================================
import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, Clock, User, AlertTriangle } from 'lucide-react'
import { apiFetch } from '../App.jsx'
import { format, parseISO } from 'date-fns'
import { toast } from 'react-toastify'

function SeverityBadge({ s }) {
    return <span className={`badge badge-${s?.toLowerCase()}`}>{s}</span>
}
function StatusBadge({ s }) {
    return <span className={`badge badge-${s?.toLowerCase()}`}>{s?.replace('_', ' ')}</span>
}

const STATUS_TRANSITIONS = {
    OPEN: ['ACKNOWLEDGED'],
    ACKNOWLEDGED: ['INVESTIGATING', 'FALSE_POSITIVE'],
    INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE'],
    RESOLVED: [],
    FALSE_POSITIVE: []
}

export default function IncidentDetail() {
    const { id } = useParams()
    const navigate = useNavigate()
    const [incident, setIncident] = useState(null)
    const [timeline, setTimeline] = useState([])
    const [notes, setNotes] = useState('')
    const [assignee, setAssignee] = useState('')
    const [saving, setSaving] = useState(false)

    const load = async () => {
        const data = await apiFetch(`/api/incidents/${id}`)
        setIncident(data.incident)
        setTimeline(data.timeline)
        setNotes(data.incident.notes || '')
        setAssignee(data.incident.assigned_to || '')
    }
    useEffect(() => { load() }, [id])

    const transition = async (newStatus) => {
        setSaving(true)
        try {
            await apiFetch(`/api/incidents/${id}`, {
                method: 'PATCH',
                body: JSON.stringify({ status: newStatus })
            })
            toast.success(`Status updated to ${newStatus}`)
            load()
        } catch (e) { toast.error(e.message) }
        finally { setSaving(false) }
    }

    const save = async () => {
        setSaving(true)
        try {
            await apiFetch(`/api/incidents/${id}`, {
                method: 'PATCH',
                body: JSON.stringify({ notes, assigned_to: assignee || undefined })
            })
            toast.success('Incident updated')
            load()
        } catch (e) { toast.error(e.message) }
        finally { setSaving(false) }
    }

    const blockIP = async () => {
        if (!incident?.source_ip) return
        try {
            await apiFetch('/api/blocklist', {
                method: 'POST',
                body: JSON.stringify({
                    ip: incident.source_ip,
                    reason: `Blocked from incident ${id.slice(0, 8)}`,
                    incident_id: id,
                    expires_hours: 24
                })
            })
            toast.success(`${incident.source_ip} added to blocklist (24h)`)
        } catch (e) { toast.error(e.message) }
    }

    if (!incident) return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: 'var(--text-muted)' }}>
            Loading incident...
        </div>
    )

    const nextStatuses = STATUS_TRANSITIONS[incident.status] || []

    return (
        <div>
            {/* Header */}
            <div className="page-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <button className="btn btn-ghost" onClick={() => navigate('/incidents')}>
                        <ArrowLeft size={14} /> Back
                    </button>
                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <h1 className="page-title" style={{ fontSize: 18 }}>
                                Incident #{id.slice(0, 8)}
                            </h1>
                            <SeverityBadge s={incident.severity} />
                            <StatusBadge s={incident.status} />
                        </div>
                        <p className="page-subtitle">{incident.attack_type} · {incident.site_id}</p>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    {incident.source_ip && (
                        <button className="btn btn-danger" onClick={blockIP}>
                            🚫 Block {incident.source_ip}
                        </button>
                    )}
                    {nextStatuses.map(s => (
                        <button key={s} className="btn btn-primary" disabled={saving} onClick={() => transition(s)}>
                            → {s.replace('_', ' ')}
                        </button>
                    ))}
                </div>
            </div>

            <div className="incident-panel">
                {/* Left: Details + Notes */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                    {/* Key Metrics */}
                    <div className="card">
                        <div className="card-header"><span className="card-title">Incident Details</span></div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                            {[
                                ['Attack Type', incident.attack_type],
                                ['Source IP', incident.source_ip || 'Multiple'],
                                ['Country', incident.source_country || '—'],
                                ['WAF Rule', incident.rule_tag || '—'],
                                ['Total Events', incident.event_count?.toLocaleString()],
                                ['Site', incident.site_id],
                                ['First Seen', incident.first_seen ? format(parseISO(incident.first_seen), 'yyyy-MM-dd HH:mm:ss') : '—'],
                                ['Last Seen', incident.last_seen ? format(parseISO(incident.last_seen), 'yyyy-MM-dd HH:mm:ss') : '—'],
                            ].map(([label, value]) => (
                                <div key={label}>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</div>
                                    <div className="mono" style={{ fontSize: 13, color: 'var(--text-primary)' }}>{value}</div>
                                </div>
                            ))}
                        </div>

                        {incident.endpoints_targeted?.length > 0 && (
                            <div style={{ marginTop: 16 }}>
                                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Targeted Endpoints</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                    {incident.endpoints_targeted.map(ep => (
                                        <code key={ep} style={{
                                            background: 'var(--bg-primary)', border: '1px solid var(--border)',
                                            padding: '2px 8px', borderRadius: 4, fontSize: 12,
                                            color: 'var(--accent-cyan)'
                                        }}>{ep}</code>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Analyst Notes */}
                    <div className="card">
                        <div className="card-header">
                            <span className="card-title">Analyst Notes</span>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Assign To</label>
                            <input className="input" value={assignee} onChange={e => setAssignee(e.target.value)} placeholder="analyst@company.com" />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Notes</label>
                            <textarea className="input" value={notes} onChange={e => setNotes(e.target.value)}
                                rows={6} placeholder="Investigation notes, findings, remediation steps..." />
                        </div>
                        <button className="btn btn-primary" disabled={saving} onClick={save}>
                            {saving ? 'Saving...' : 'Save Notes'}
                        </button>
                    </div>
                </div>

                {/* Right: Timeline */}
                <div className="card" style={{ alignSelf: 'start' }}>
                    <div className="card-header">
                        <span className="card-title"><Clock size={14} style={{ verticalAlign: 'middle' }} /> Timeline</span>
                    </div>
                    {timeline.length === 0 && (
                        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No timeline events yet</p>
                    )}
                    {timeline.map(entry => (
                        <div key={entry.id} className="timeline-entry">
                            <div className="timeline-dot" />
                            <div>
                                <div className="timeline-actor">
                                    {entry.actor === 'system'
                                        ? <span style={{ color: 'var(--accent-blue)' }}>🤖 System</span>
                                        : <span><User size={11} /> {entry.actor}</span>
                                    }
                                </div>
                                <div className="timeline-detail">{entry.detail}</div>
                                <div className="timeline-time">
                                    {entry.created_at ? format(parseISO(entry.created_at), 'yyyy-MM-dd HH:mm:ss') : ''}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    )
}
