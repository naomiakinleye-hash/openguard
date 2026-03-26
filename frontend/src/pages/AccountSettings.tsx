import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../contexts/ToastContext';

export default function AccountSettings() {
  const { logout } = useAuth();
  const { addToast } = useToast();
  const navigate = useNavigate();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [saving, setSaving] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (newPassword && newPassword !== confirmPassword) {
      addToast('New passwords do not match', 'error');
      return;
    }
    if (!newUsername && !newPassword) {
      addToast('Enter a new username or new password', 'error');
      return;
    }
    setSaving(true);
    api.updateAccount(currentPassword, newUsername, newPassword)
      .then(() => {
        addToast('Account updated — please log in again', 'success');
        logout();
        navigate('/login');
      })
      .catch((err: unknown) =>
        addToast(err instanceof Error ? err.message : 'Update failed', 'error'),
      )
      .finally(() => setSaving(false));
  }

  const cardStyle: React.CSSProperties = {
    background: '#1e293b',
    borderRadius: '12px',
    border: '1px solid #334155',
    padding: '2rem',
    maxWidth: '480px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '0.8125rem',
    fontWeight: 600,
    color: '#94a3b8',
    marginBottom: '0.375rem',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: '8px',
    color: '#f1f5f9',
    fontSize: '0.9375rem',
    padding: '0.625rem 0.875rem',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const sectionHeadStyle: React.CSSProperties = {
    fontSize: '0.6875rem',
    fontWeight: 700,
    color: '#475569',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    marginBottom: '0.875rem',
    marginTop: '1.5rem',
    paddingBottom: '0.375rem',
    borderBottom: '1px solid #1e293b',
  };

  return (
    <div style={{ padding: '2rem' }}>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.5rem' }}>
        👤 Account Settings
      </h1>
      <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '2rem' }}>
        Change your username or password. You will be signed out after saving.
      </p>

      <div style={cardStyle}>
        <form onSubmit={handleSubmit}>
          {/* Current password — always required to authorise changes */}
          <div style={sectionHeadStyle}>Verify identity</div>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={labelStyle}>Current password</label>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
              style={inputStyle}
              placeholder="Enter your current password"
            />
          </div>

          {/* New username */}
          <div style={sectionHeadStyle}>Change username (optional)</div>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={labelStyle}>New username</label>
            <input
              type="text"
              autoComplete="username"
              value={newUsername}
              onChange={e => setNewUsername(e.target.value)}
              style={inputStyle}
              placeholder="Leave blank to keep current username"
            />
          </div>

          {/* New password */}
          <div style={sectionHeadStyle}>Change password (optional)</div>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={labelStyle}>New password</label>
            <input
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              style={inputStyle}
              placeholder="Leave blank to keep current password"
            />
          </div>
          <div style={{ marginBottom: '1.75rem' }}>
            <label style={labelStyle}>Confirm new password</label>
            <input
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              style={inputStyle}
              placeholder="Repeat new password"
            />
          </div>

          <button
            type="submit"
            disabled={saving}
            style={{
              background: saving ? '#1e3a5f' : '#2563eb',
              color: '#fff',
              border: 'none',
              borderRadius: '8px',
              padding: '0.75rem 1.5rem',
              fontWeight: 700,
              fontSize: '0.9375rem',
              cursor: saving ? 'not-allowed' : 'pointer',
              width: '100%',
              transition: 'background 0.2s',
            }}
          >
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </form>
      </div>
    </div>
  );
}
