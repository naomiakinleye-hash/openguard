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
import ModelSettings from './pages/ModelSettings';
import Login from './pages/Login';
import NotFound from './pages/NotFound';

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
                <Route path="models" element={<ModelSettings />} />
              </Route>
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
