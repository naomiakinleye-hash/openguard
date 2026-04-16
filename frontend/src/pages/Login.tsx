import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../contexts/AuthContext';

// Block any input that looks like a script injection attempt
function containsScript(value: string): boolean {
  return /<script|javascript:|on\w+\s*=/i.test(value);
}

// Sanitize a string for safe display — strips HTML tags
function sanitize(value: string): string {
  return value.replace(/[<>"'&]/g, (c) =>
    ({ '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;' }[c] ?? c)
  );
}

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 60_000; // 1 minute

export default function Login() {
  const { login }    = useAuth();
  const navigate     = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ username?: string; password?: string }>({});
  const [loading, setLoading]   = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [lockedUntil, setLockedUntil] = useState<number | null>(null);

  function validate(): boolean {
    const errs: { username?: string; password?: string } = {};

    if (!username.trim()) {
      errs.username = 'Username is required';
    } else if (username.trim().length < 2) {
      errs.username = 'Username must be at least 2 characters';
    } else if (containsScript(username)) {
      errs.username = 'Username contains invalid characters';
    }

    if (!password) {
      errs.password = 'Password is required';
    } else if (password.length < 4) {
      errs.password = 'Password must be at least 4 characters';
    } else if (containsScript(password)) {
      errs.password = 'Password contains invalid characters';
    }

    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');

    // Check lockout
    if (lockedUntil && Date.now() < lockedUntil) {
      const secs = Math.ceil((lockedUntil - Date.now()) / 1000);
      setError(`Too many failed attempts. Try again in ${secs} seconds.`);
      return;
    }

    if (!validate()) return;

    setLoading(true);
    try {
      const res = await api.login(sanitize(username.trim()), password);
      login(res.token);
      setAttempts(0);
      navigate('/');
    } catch (err: unknown) {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);

      if (newAttempts >= MAX_ATTEMPTS) {
        setLockedUntil(Date.now() + LOCKOUT_MS);
        setError('Too many failed attempts. Account locked for 60 seconds.');
      } else {
        const remaining = MAX_ATTEMPTS - newAttempts;
        const msg = err instanceof Error ? err.message : 'Login failed';
        setError(`${msg}. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`);
      }
    } finally {
      setLoading(false);
    }
  }

  function handleUsernameChange(e: React.ChangeEvent<HTMLInputElement>) {
    setUsername(e.target.value);
    if (fieldErrors.username) setFieldErrors(f => ({ ...f, username: undefined }));
  }

  function handlePasswordChange(e: React.ChangeEvent<HTMLInputElement>) {
    setPassword(e.target.value);
    if (fieldErrors.password) setFieldErrors(f => ({ ...f, password: undefined }));
  }

  const isLocked = !!(lockedUntil && Date.now() < lockedUntil);

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <span className="login-logo">⚔️</span>
          <h1 className="login-title">OpenGuard v5</h1>
        </div>
        <p className="login-subtitle">Security Operations Console</p>

        {error && (
          <div className="error-msg" role="alert" aria-live="polite">
            ⚠️ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form" noValidate>

          <label className="login-label" htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            className={`login-input${fieldErrors.username ? ' input-error' : ''}`}
            value={username}
            onChange={handleUsernameChange}
            autoComplete="username"
            aria-invalid={!!fieldErrors.username}
            aria-describedby={fieldErrors.username ? 'username-error' : undefined}
            disabled={isLocked}
            maxLength={64}
          />
          {fieldErrors.username && (
            <p id="username-error" className="field-error" role="alert">
              {fieldErrors.username}
            </p>
          )}

          <label className="login-label" htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            className={`login-input${fieldErrors.password ? ' input-error' : ''}`}
            value={password}
            onChange={handlePasswordChange}
            autoComplete="current-password"
            aria-invalid={!!fieldErrors.password}
            aria-describedby={fieldErrors.password ? 'password-error' : undefined}
            disabled={isLocked}
            maxLength={128}
          />
          {fieldErrors.password && (
            <p id="password-error" className="field-error" role="alert">
              {fieldErrors.password}
            </p>
          )}

          <button
            type="submit"
            className="login-btn"
            disabled={loading || isLocked}
          >
            {loading ? 'Signing in…' : isLocked ? 'Locked' : 'Sign In'}
          </button>

        </form>

        {attempts > 0 && !isLocked && (
          <p style={{ fontSize: '0.75rem', color: '#64748b', textAlign: 'center', marginTop: '0.5rem' }}>
            {MAX_ATTEMPTS - attempts} attempt{MAX_ATTEMPTS - attempts === 1 ? '' : 's'} remaining before lockout
          </p>
        )}
      </div>
    </div>
  );
}
