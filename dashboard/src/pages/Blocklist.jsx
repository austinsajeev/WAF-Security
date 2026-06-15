// =============================================================================
// Blocklist Page — Manage IP blocklist
// =============================================================================
import { useState, useEffect } from 'react'
import { Shield, Plus } from 'lucide-react'
import { apiFetch } from '../App.jsx'
import { format, parseISO } from 'date-fns'
import { toast } from 'react-toastify'

export default function Blocklist() {
    const [entries, setEntries] = useState([])
    const [loading, setLoading] = useState(true)
    const [showAdd, setShowAdd] = useState(false)
    const [activeTab, setActiveTab] = useState('all') // 'all', 'auto', 'manual'
    const [form, setForm] = useState({ ip: '', reason: '', expires_hours: '' })

    const load = async () => {
        setLoading(true)
        try {
            const data = await apiFetch('/api/blocklist?active_only=true')
            setEntries(data.blocklist || [])
        } catch (e) { toast.error(e.message) }
        finally { setLoading(false) }
    }

    useEffect(() => { load() }, [])

    const addBlock = async () => {
        try {
            await apiFetch('/api/blocklist', {
                method: 'POST',
                body: JSON.stringify({
                    ip: form.ip,
                    reason: form.reason,
                    expires_hours: form.expires_hours ? Number(form.expires_hours) : null
                })
            })
            toast.success(`${form.ip} blocked successfully`)
            setForm({ ip: '', reason: '', expires_hours: '' })
            setShowAdd(false)
            load()
        } catch (e) { toast.error(e.message) }
    }

    return (
        <div>
            <div className="page-header">
                <div>
                    <h1 className="page-title">IP Blocklist</h1>
                    <p className="page-subtitle">{entries.length} active blocks</p>
                </div>
                <button className="btn btn-primary" onClick={() => setShowAdd(!showAdd)}>
                    <Plus size={14} /> Add IP
                </button>
            </div>

            {/* Add IP Form */}
            {showAdd && (
                <div className="card" style={{ marginBottom: 16 }}>
                    <div className="card-title" style={{ marginBottom: 16 }}>Block New IP</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 1fr', gap: 12 }}>
                        <div>
                            <label className="form-label">IP Address</label>
                            <input className="input" placeholder="192.168.1.1" value={form.ip}
                                onChange={e => setForm(f => ({ ...f, ip: e.target.value }))} />
                        </div>
                        <div>
                            <label className="form-label">Reason</label>
                            <input className="input" placeholder="Manual block — brute force" value={form.reason}
                                onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} />
                        </div>
                        <div>
                            <label className="form-label">Expires (hours, blank = permanent)</label>
                            <input className="input" type="number" placeholder="24" value={form.expires_hours}
                                onChange={e => setForm(f => ({ ...f, expires_hours: e.target.value }))} />
                        </div>
                    </div>
                    <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                        <button className="btn btn-primary" onClick={addBlock} disabled={!form.ip || !form.reason}>
                            Block IP
                        </button>
                        <button className="btn btn-ghost" onClick={() => setShowAdd(false)}>Cancel</button>
                    </div>
                </div>
            )}

            {/* Tabs */}
            <div style={{ display: 'flex', gap: 16, marginBottom: 16, borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
                <button 
                    className={`btn ${activeTab === 'all' ? 'btn-primary' : 'btn-ghost'}`}
                    onClick={() => setActiveTab('all')}
                >
                    All Blocks
                </button>
                <button 
                    className={`btn ${activeTab === 'auto' ? 'btn-primary' : 'btn-ghost'}`}
                    onClick={() => setActiveTab('auto')}
                >
                    Auto-Blocked
                </button>
                <button 
                    className={`btn ${activeTab === 'manual' ? 'btn-primary' : 'btn-ghost'}`}
                    onClick={() => setActiveTab('manual')}
                >
                    Manual Blocks
                </button>
            </div>

            {/* Table */}
            <div className="card">
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th><Shield size={11} /> IP Address</th>
                                <th>Reason</th>
                                <th>Source</th>
                                <th>Blocked By</th>
                                <th>Blocked At</th>
                                <th>Expires</th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>Loading...</td></tr>
                            )}
                            {!loading && entries.length === 0 && (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                                    No active blocks — system is in observation mode
                                </td></tr>
                            )}
                            {!loading && entries.filter(e => {
                                if (activeTab === 'auto') return e.source === 'AUTO' || e.blocked_by === 'correlation_engine' || e.blocked_by === 'ml_worker';
                                if (activeTab === 'manual') return e.source !== 'AUTO' && e.blocked_by !== 'correlation_engine' && e.blocked_by !== 'ml_worker';
                                return true;
                            }).length === 0 && entries.length > 0 && (
                                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                                    No blocks in this category
                                </td></tr>
                            )}
                            {entries.filter(e => {
                                if (activeTab === 'auto') return e.source === 'AUTO' || e.blocked_by === 'correlation_engine' || e.blocked_by === 'ml_worker';
                                if (activeTab === 'manual') return e.source !== 'AUTO' && e.blocked_by !== 'correlation_engine' && e.blocked_by !== 'ml_worker';
                                return true;
                            }).map(e => (
                                <tr key={e.ip}>
                                    <td className="mono" style={{ color: 'var(--critical)', fontWeight: 600 }}>{e.ip}</td>
                                    <td style={{ maxWidth: 280 }}>{e.reason}</td>
                                    <td><span className="badge badge-info">{e.source}</span></td>
                                    <td style={{ color: 'var(--text-muted)' }}>{e.blocked_by}</td>
                                    <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                                        {e.blocked_at ? format(parseISO(e.blocked_at), 'yyyy-MM-dd HH:mm') : '—'}
                                    </td>
                                    <td className="mono" style={{ color: e.expires_at ? 'var(--medium)' : 'var(--critical)', fontSize: 12 }}>
                                        {e.expires_at ? format(parseISO(e.expires_at), 'yyyy-MM-dd HH:mm') : '∞ Permanent'}
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
