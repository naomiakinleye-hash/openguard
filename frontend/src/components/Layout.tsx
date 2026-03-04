import { NavLink, Outlet } from 'react-router-dom';
import './Layout.css';

const NAV = [
  { to: '/', label: '🛡️ Dashboard', end: true },
  { to: '/events', label: '📡 Events' },
  { to: '/incidents', label: '🚨 Incidents' },
  { to: '/audit', label: '📋 Audit Log' },
];

export default function Layout() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="sidebar-logo">⚔️</span>
          <span className="sidebar-title">OpenGuard v5</span>
        </div>
        <nav className="sidebar-nav">
          {NAV.map(({ to, label, end }) => (
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
          <span className="sidebar-footer-text">DSHub Ltd.</span>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
