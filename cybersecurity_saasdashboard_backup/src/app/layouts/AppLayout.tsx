import { Outlet } from 'react-router';
import Sidebar from '../components/Sidebar';

export default function AppLayout() {
  return (
    <div className="flex h-screen bg-gradient-to-br from-gray-50 via-white to-gray-100">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
