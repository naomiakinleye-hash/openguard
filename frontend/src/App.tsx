import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Events from './pages/Events';
import Incidents from './pages/Incidents';
import AuditLog from './pages/AuditLog';
import Sensors from './pages/Sensors';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="events" element={<Events />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="audit" element={<AuditLog />} />
          <Route path="sensors" element={<Sensors />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

