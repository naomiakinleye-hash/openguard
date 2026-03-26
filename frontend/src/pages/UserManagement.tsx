import { useEffect, useState } from 'react';
import { api, type UserRecord } from '../api';
import { useToast } from '../contexts/ToastContext';

const ROLES = ['viewer', 'analyst', 'operator', 'admin'] as const;
type Role = typeof ROLES[number];

export default function UserManagement() {
  const { addToast } = useToast();
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // New user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<Role>('viewer');
  const [creating, setCreating] = useState(false);

  // Edit state — stores { role, new_password } per username
  const [editRole, setEditRole] = useState<Record<string, Role>>({});
  const [editPwd, setEditPwd] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);

  async function load() {
    try {
      const res = await api.listUsers();
      setUsers(res.users);
      const roles: Record<string, Role> = {};
      const pwds: Record<string, string> = {};
      for (const u of res.users) { roles[u.username] = u.role; pwds[u.username] = ''; }
      setEditRole(roles);
      setEditPwd(pwds);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newUsername || !newPassword) return;
    setCreating(true);
    try {
      await api.createUser(newUsername, newPassword, newRole);
      addToast(`User "${newUsername}" created`, 'success');
      setNewUsername(''); setNewPassword(''); setNewRole('viewer');
      await load();
    } catch (err: unknown) {
      addToast(`Create failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setCreating(false); }
  }

  async function handleSave(username: string) {
    setSaving(username);
    try {
      const data: { role?: string; new_password?: string } = { role: editRole[username] };
      if (editPwd[username]) data.new_password = editPwd[username];
      await api.updateUser(username, data);
      addToast(`User "${username}" updated`, 'success');
      setEditPwd((p) => ({ ...p, [username]: '' }));
      await load();
    } catch (err: unknown) {
      addToast(`Update failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setSaving(null); }
  }

  async function handleDelete(username: string) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    try {
      await api.deleteUser(username);
      addToast(`User "${username}" deleted`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Delete failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2>User Management</h2>
        <p>Manage console operator accounts and role assignments.</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {/* Create user form */}
      <div className="card" style={{ marginBottom: '1.5rem', maxWidth: '600px' }}>
        <h3 style={{ margin: '0 0 1rem' }}>Add User</h3>
        <form onSubmit={handleCreate} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Username</label>
            <input
              className="input-field"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="username"
              required
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Password</label>
            <input
              className="input-field"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="password"
              required
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Role</label>
            <select className="input-field" value={newRole} onChange={(e) => setNewRole(e.target.value as Role)}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <button className="btn-approve" type="submit" disabled={creating}>
            {creating ? '…' : '+ Add'}
          </button>
        </form>
      </div>

      {/* User table */}
      {loading ? <div className="loading">Loading…</div> : (
        <div className="card" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>New Password</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username}>
                  <td><code>{u.username}</code></td>
                  <td>
                    <select
                      className="input-field"
                      style={{ fontSize: '0.85rem', padding: '0.25rem 0.5rem' }}
                      value={editRole[u.username] ?? u.role}
                      onChange={(e) => setEditRole((p) => ({ ...p, [u.username]: e.target.value as Role }))}
                    >
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td>
                    <input
                      className="input-field"
                      type="password"
                      style={{ fontSize: '0.85rem', padding: '0.25rem 0.5rem' }}
                      placeholder="(unchanged)"
                      value={editPwd[u.username] ?? ''}
                      onChange={(e) => setEditPwd((p) => ({ ...p, [u.username]: e.target.value }))}
                    />
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      className="btn-approve"
                      style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
                      disabled={saving === u.username}
                      onClick={() => handleSave(u.username)}
                    >
                      {saving === u.username ? '…' : 'Save'}
                    </button>
                    <button
                      className="btn-deny"
                      style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
                      onClick={() => handleDelete(u.username)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
