import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Layout.css';

const ROLE_ORDER: Record<string, number> = {
  viewer: 0, analyst: 1, operator: 2, admin: 3,
};

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
  minRole?: string;
}

const NAV: NavItem[] = [
  { to: '/', label: '🛡️ Dashboard', end: true },
  { to: '/events', label: '📡 Events' },
  { to: '/incidents', label: '🚨 Incidents' },
  { to: '/audit', label: '📋 Audit Log' },
  { to: '/sensors', label: '🔬 Sensors' },
  { to: '/hostguard', label: '🖥️ HostGuard' },
  { to: '/networkguard', label: '🌐 NetworkGuard' },
  { to: '/commsguard', label: '💬 CommsGuard' },
  { to: '/agentguard', label: '🤖 AgentGuard' },
  { to: '/modelguard', label: '🧠 ModelGuard' },
  { to: '/supplychain', label: '📦 Supply Chain' },
  { to: '/webhooks', label: '🔔 Webhooks', minRole: 'operator' },
  { to: '/users', label: '👥 Users', minRole: 'admin' },
  { to: '/account', label: '👤 Account' },
];

export default function Layout() {
  const { logout, role } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate('/login');
  }

  const visibleNav = NAV.filter((item) => {
    if (!item.minRole) return true;
    return (ROLE_ORDER[role] ?? -1) >= (ROLE_ORDER[item.minRole] ?? 0);
  });

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="sidebar-logo">⚔️</span>
          <span className="sidebar-title">OpenGuard v5</span>
        </div>
        <nav className="sidebar-nav">
          {visibleNav.map(({ to, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `sidebar-link${isActive ? ' sidebar-link--active' : ''}`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <span className="sidebar-user-badge">{role || 'viewer'}</span>
          </div>
          <button className="logout-btn" onClick={handleLogout}>
            🚪 Logout
          </button>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
