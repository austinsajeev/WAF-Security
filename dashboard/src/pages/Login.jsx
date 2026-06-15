// =============================================================================
// Login Page — JWT + MFA two-step authentication
// =============================================================================
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth, apiFetch, API_BASE } from '../App.jsx'
import { toast } from 'react-toastify'

export default function Login() {
    const { login } = useAuth()
    const navigate = useNavigate()
    const [step, setStep] = useState('credentials') // 'credentials' | 'mfa'
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [totp, setTotp] = useState('')
    const [mfaToken, setMfaToken] = useState('')
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    const submitCredentials = async (e) => {
        e.preventDefault()
        setLoading(true); setError('')
        try {
            const form = new URLSearchParams({ username, password })
            const res = await fetch(`${API_BASE}/api/auth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: form,
            })
            const data = await res.json()
            if (!res.ok) throw new Error(data.detail || 'Login failed')

            if (data.requires_mfa) {
                setMfaToken(data.mfa_token)
                setStep('mfa')
            } else {
                login(data.access_token)
                navigate('/')
            }
        } catch (e) { setError(e.message) }
        finally { setLoading(false) }
    }

    const submitMFA = async (e) => {
        e.preventDefault()
        setLoading(true); setError('')
        try {
            const data = await apiFetch('/api/auth/mfa/verify', {
                method: 'POST',
                body: JSON.stringify({ mfa_token: mfaToken, totp_code: totp })
            })
            login(data.access_token)
            navigate('/')
        } catch (e) { setError(e.message) }
        finally { setLoading(false) }
    }

    return (
        <div className="login-page">
            <div className="login-card">
                <div className="login-logo">🛡️ AegisAI-X</div>
                <div className="login-tagline">Security Operations Center</div>

                {step === 'credentials' ? (
                    <form onSubmit={submitCredentials}>
                        <div className="form-group">
                            <label className="form-label">Username</label>
                            <input className="input" value={username} autoComplete="username"
                                onChange={e => setUsername(e.target.value)} required />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input className="input" type="password" value={password} autoComplete="current-password"
                                onChange={e => setPassword(e.target.value)} required />
                        </div>
                        {error && <div className="form-error">{error}</div>}
                        <button className="btn btn-primary" type="submit" disabled={loading}
                            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}>
                            {loading ? 'Authenticating...' : 'Sign In'}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={submitMFA}>
                        <div style={{ textAlign: 'center', marginBottom: 24 }}>
                            <div style={{ fontSize: 32 }}>🔐</div>
                            <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginTop: 8 }}>
                                Enter your authenticator code
                            </p>
                        </div>
                        <div className="form-group">
                            <label className="form-label">6-Digit TOTP Code</label>
                            <input className="input" value={totp} onChange={e => setTotp(e.target.value)}
                                maxLength={6} placeholder="000000" autoFocus
                                style={{ textAlign: 'center', letterSpacing: 8, fontSize: 20 }} />
                        </div>
                        {error && <div className="form-error">{error}</div>}
                        <button className="btn btn-primary" type="submit" disabled={loading || totp.length !== 6}
                            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}>
                            {loading ? 'Verifying...' : 'Verify'}
                        </button>
                        <button type="button" className="btn btn-ghost"
                            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
                            onClick={() => { setStep('credentials'); setError('') }}>
                            ← Back
                        </button>
                    </form>
                )}

                <p style={{ textAlign: 'center', marginTop: 24, fontSize: 11, color: 'var(--text-muted)' }}>
                    AegisAI-X v2.0 · Session expires in 60 minutes
                </p>
            </div>
        </div>
    )
}
