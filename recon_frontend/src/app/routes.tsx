import { createBrowserRouter } from 'react-router';
import RequireAuth from './components/auth/RequireAuth';
import ReconLayout from './layouts/ReconLayout';
import Login from './pages/Login';
import Dashboard from './pages/recon/Dashboard';
import ReconDashboard from './pages/recon/ReconDashboard';
import AssetInventory from './pages/recon/AssetInventory';
import NewScan from './pages/recon/NewScan';
import ScanResults from './pages/recon/ScanResults';

export const router = createBrowserRouter([
  {
    path: '/signin',
    Component: Login,
  },
  {
    Component: RequireAuth,
    children: [
      {
        path: '/',
        Component: ReconLayout,
        children: [
          { index: true, Component: Dashboard },
          { path: 'overview', Component: ReconDashboard },
          { path: 'inventory', Component: AssetInventory },
          { path: 'new-scan', Component: NewScan },
          { path: 'scan/:id', Component: ScanResults },
        ],
      },
    ],
  },
  // Legacy SPA route (not used in container deployment because backend owns /login).
  {
    path: '/login',
    loader: () => {
      window.location.replace('/signin');
      return null;
    },
  },
]);
