import { createContext, useContext, useState, type ReactNode } from 'react';

interface AuthContextValue {
  token: string | null;
  role: string;
  login: (token: string) => void;
  logout: () => void;
}

/** Decode the JWT payload (middle base64 segment) to extract claims. */
function decodeJWTPayload(token: string): Record<string, unknown> {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return {};
  }
}

function roleFromToken(tok: string | null): string {
  if (!tok) return '';
  const payload = decodeJWTPayload(tok);
  return typeof payload.role === 'string' ? payload.role : '';
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('og_token'));
  const [role, setRole] = useState<string>(() => roleFromToken(localStorage.getItem('og_token')));

  function login(tok: string) {
    localStorage.setItem('og_token', tok);
    setToken(tok);
    setRole(roleFromToken(tok));
  }

  function logout() {
    localStorage.removeItem('og_token');
    setToken(null);
    setRole('');
  }

  return (
    <AuthContext.Provider value={{ token, role, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
