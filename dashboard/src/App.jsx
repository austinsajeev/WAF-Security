// =============================================================================
// AegisAI-X SOC Dashboard — Main App
// =============================================================================
import { useState, useEffect, createContext, useContext } from 'react'
import { BrowserRouter, Routes, Route, Navigate, NavLink, useNavigate } from 'react-router-dom'
import { ToastContainer, toast } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import {
    LayoutDashboard, ShieldAlert, Globe, List,
    LogOut, Lock, Settings, RefreshCw, Brain
} from 'lucide-react'
import './index.css'

// Pages
import Login from './pages/Login.jsx'
import Overview from './pages/Overview.jsx'
import Incidents from './pages/Incidents.jsx'
import IncidentDetail from './pages/IncidentDetail.jsx'
import Blocklist from './pages/Blocklist.jsx'
import Sites from './pages/Sites.jsx'
import MLStatus from './pages/MLStatus.jsx'

// ---------------------------------------------------------------------------
// Auth Context
// ---------------------------------------------------------------------------
const AuthContext = createContext(null)
export const useAuth = () => useContext(AuthContext)

function AuthProvider({ children }) {
    const [token, setToken] = useState(localStorage.getItem('aegisai_token'))
    const [user, setUser] = useState(null)

    const login = (newToken) => {
        localStorage.setItem('aegisai_token', newToken)
        setToken(newToken)
    }
    const logout = () => {
        localStorage.removeItem('aegisai_token')
        setToken(null); setUser(null)
    }

    return (
        <AuthContext.Provider value={{ token, user, login, logout }}>
            {children}
        </AuthContext.Provider>
    )
}

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------
export const API_BASE = ''

export async function apiFetch(path, options = {}) {
    const token = localStorage.getItem('aegisai_token')
    const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...options.headers,
        },
    })
    if (res.status === 401) {
        localStorage.removeItem('aegisai_token')
        window.location.href = '/login'
        return
    }
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
        throw new Error(err.detail || 'API error')
    }
    return res.json()
}

// ---------------------------------------------------------------------------
// Protected Route
// ---------------------------------------------------------------------------
function ProtectedRoute({ children }) {
    const { token } = useAuth()
    if (!token) return <Navigate to="/login" replace />
    return children
}

// ---------------------------------------------------------------------------
// App Shell (Sidebar + Topbar)
// ---------------------------------------------------------------------------
function AppShell({ children }) {
    const { logout } = useAuth()
    const [clock, setClock] = useState(new Date())

    useEffect(() => {
        const t = setInterval(() => setClock(new Date()), 1000)
        return () => clearInterval(t)
    }, [])

    const navItems = [
        { to: '/', icon: <LayoutDashboard size={16} />, label: 'Overview' },
        { to: '/incidents', icon: <ShieldAlert size={16} />, label: 'Incidents' },
        { to: '/sites', icon: <Globe size={16} />, label: 'Sites' },
        { to: '/blocklist', icon: <Lock size={16} />, label: 'Blocklist' },
        { to: '/ml', icon: <Brain size={16} />, label: 'ML Status' },
    ]

    return (
        <div className="app-shell">
            {/* Top Bar */}
            <header className="topbar">
                <div className="topbar-logo">
                    <span className="shield">🛡️</span>
                    AegisAI-X
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>SOC</span>
                </div>
                <div className="topbar-right">
                    <div className="status-dot" title="All systems operational" />
                    <span className="topbar-time">
                        {clock.toUTCString().replace('GMT', 'UTC')}
                    </span>
                    <button className="btn btn-ghost" onClick={logout} style={{ gap: 4 }}>
                        <LogOut size={14} /> Logout
                    </button>
                </div>
            </header>

            {/* Sidebar */}
            <nav className="sidebar">
                {navItems.map(({ to, icon, label }) => (
                    <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                    >
                        {icon}
                        {label}
                    </NavLink>
                ))}
            </nav>

            {/* Main */}
            <main className="main-content">
                {children}
            </main>
        </div>
    )
}

// ---------------------------------------------------------------------------
// Root App
// ---------------------------------------------------------------------------
export default function App() {
    return (
        <AuthProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="/ml" element={
                        <AppShell><MLStatus /></AppShell>
                    } />
                    <Route path="/*" element={
                        <ProtectedRoute>
                            <AppShell>
                                <Routes>
                                    <Route path="/" element={<Overview />} />
                                    <Route path="/incidents" element={<Incidents />} />
                                    <Route path="/incidents/:id" element={<IncidentDetail />} />
                                    <Route path="/sites" element={<Sites />} />
                                    <Route path="/blocklist" element={<Blocklist />} />
                                </Routes>
                            </AppShell>
                        </ProtectedRoute>
                    } />
                </Routes>
            </BrowserRouter>
            <ToastContainer
                theme="dark" position="bottom-right"
                toastStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
            />
        </AuthProvider>
    )
}
