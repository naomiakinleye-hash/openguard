import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ToastProvider } from './contexts/ToastContext';
import ToastContainer from './components/ToastContainer';
import ProtectedRoute from './components/ProtectedRoute';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Events from './pages/Events';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import AuditLog from './pages/AuditLog';
import Sensors from './pages/Sensors';
import Login from './pages/Login';
import NotFound from './pages/NotFound';
import CommsGuard from './pages/CommsGuard';
import AgentGuard from './pages/AgentGuard';
import ModelGuard from './pages/ModelGuard';
import HostGuard from './pages/HostGuard';
import NetworkGuard from './pages/NetworkGuard';
import AccountSettings from './pages/AccountSettings';
import UserManagement from './pages/UserManagement';
import WebhookSettings from './pages/WebhookSettings';
import SupplyChainGuard from './pages/SupplyChainGuard';

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <ToastContainer />
        <BrowserRouter>
          <Routes>
            <Route path="login" element={<Login />} />
            <Route element={<ProtectedRoute />}>
              <Route element={<Layout />}>
                <Route index element={<Dashboard />} />
                <Route path="events" element={<Events />} />
                <Route path="incidents" element={<Incidents />} />
                <Route path="incidents/:id" element={<IncidentDetail />} />
                <Route path="audit" element={<AuditLog />} />
                <Route path="sensors" element={<Sensors />} />
                <Route path="commsguard" element={<CommsGuard />} />
                <Route path="agentguard" element={<AgentGuard />} />
                <Route path="modelguard" element={<ModelGuard />} />
                <Route path="hostguard" element={<HostGuard />} />
                <Route path="networkguard" element={<NetworkGuard />} />
                <Route path="account" element={<AccountSettings />} />
                <Route path="users" element={<UserManagement />} />
                <Route path="webhooks" element={<WebhookSettings />} />
                <Route path="supplychain" element={<SupplyChainGuard />} />
              </Route>
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
