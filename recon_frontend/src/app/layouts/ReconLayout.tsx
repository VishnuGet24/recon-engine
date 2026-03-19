import { Link, Outlet, useLocation } from 'react-router';
import { Activity, LayoutDashboard, LogOut, Package, Shield } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

import { useAuth } from '../context/AuthContext';
import { getSystemHealth, SystemHealthResponse } from '../../api/system';
import { handleApiError } from '../../utils/errorHandler';

export default function ReconLayout() {
  const location = useLocation();
  const { logout, user } = useAuth();
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      try {
        const data = await getSystemHealth();
        if (mounted) setHealth(data);
      } catch (error) {
        if (mounted) setHealth(null);
        handleApiError(error);
      }
    };

    void load();
    const id = window.setInterval(load, 60000);
    return () => {
      mounted = false;
      window.clearInterval(id);
    };
  }, []);

  const statusUi = useMemo(() => {
    const status = health?.status || 'operational';
    if (status === 'down') return { dot: 'bg-red-500', label: 'System Unavailable' };
    if (status === 'degraded') return { dot: 'bg-yellow-500', label: 'Degraded Performance' };
    return { dot: 'bg-green-500', label: 'All Systems Operational' };
  }, [health]);

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/inventory', label: 'Asset Inventory', icon: Package },
    { path: '/new-scan', label: 'New Scan', icon: Activity },
  ];

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-gray-200 flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-gray-900">SF Recon Engine</h1>
              <p className="text-xs text-gray-500">{user?.name || user?.email || 'Security Platform'}</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`
                  flex items-center gap-3 px-4 py-3 rounded-xl transition-all
                  ${active 
                    ? 'bg-gradient-to-r from-blue-500 to-blue-600 text-white shadow-lg shadow-blue-500/30' 
                    : 'text-gray-700 hover:bg-gray-100'
                  }
                `}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200">
          <button
            type="button"
            onClick={() => void logout()}
            className="mb-3 flex w-full items-center justify-center gap-2 rounded-xl border border-gray-200 px-4 py-3 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
          <div className="px-4 py-3 rounded-xl bg-gray-50">
            <p className="text-xs text-gray-500 mb-1">System Status</p>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${statusUi.dot}`}></div>
              <span className="text-sm text-gray-700">{statusUi.label}</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
