import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { Clock, Globe, Search, Server } from 'lucide-react';

import { ApiError, listScans, ScanRecord, startScan } from '../lib/api';
import { useAuth } from '../context/AuthContext';

export default function NewScan() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState<'passive' | 'active' | 'full'>('passive');
  const [recentScans, setRecentScans] = useState<ScanRecord[]>([]);
  const [loadingRecent, setLoadingRecent] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canActive = useMemo(() => user?.permissions?.includes('scan:active') ?? false, [user]);
  const isAdmin = useMemo(() => user?.roles?.includes('admin') ?? false, [user]);

  useEffect(() => {
    if (isAdmin) {
      setScanMode('full');
    } else if (canActive) {
      setScanMode('active');
    } else {
      setScanMode('passive');
    }
  }, [canActive, isAdmin]);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        const data = await listScans();
        if (mounted) {
          setRecentScans(data.scans.slice(0, 8));
        }
      } catch {
        if (mounted) {
          setRecentScans([]);
        }
      } finally {
        if (mounted) {
          setLoadingRecent(false);
        }
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!target.trim()) {
      setError('Target is required');
      return;
    }

    setSubmitting(true);
    try {
      const data = await startScan(target.trim(), scanMode);
      navigate(`/scan/${data.scan.id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setError('You do not have permission to run this scan mode.');
        } else {
          setError(err.message);
        }
      } else {
        setError('Failed to start scan');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900 mb-2">New Security Scan</h1>
        <p className="text-gray-500">Enter a target URL or IP address to begin reconnaissance</p>
      </div>

      <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-8 border border-gray-100 mb-8">
        <form onSubmit={handleStartScan} className="space-y-5">
          <div>
            <label htmlFor="target" className="block text-sm font-medium text-gray-700 mb-3">
              Target URL or IP Address
            </label>
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  id="target"
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or 192.168.1.1"
                  className="w-full pl-12 pr-4 py-4 rounded-2xl border border-gray-200 bg-white/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all text-lg"
                />
              </div>
              <button
                type="submit"
                disabled={submitting}
                className="px-8 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-2xl font-medium shadow-lg hover:shadow-xl transition-all hover:scale-[1.02] active:scale-[0.98] whitespace-nowrap disabled:opacity-60"
              >
                {submitting ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="flex items-center gap-3 p-4 rounded-2xl border-2 border-gray-200 cursor-pointer hover:border-blue-500 transition-all">
              <input
                type="radio"
                name="scan_mode"
                value="passive"
                checked={scanMode === 'passive'}
                onChange={() => setScanMode('passive')}
              />
              <div>
                <p className="font-medium text-gray-900">Passive Scan</p>
                <p className="text-xs text-gray-500">basic role allowed</p>
              </div>
            </label>
            <label className={`flex items-center gap-3 p-4 rounded-2xl border-2 transition-all ${canActive ? 'border-gray-200 cursor-pointer hover:border-blue-500' : 'border-gray-100 opacity-50 cursor-not-allowed'}`}>
              <input
                type="radio"
                name="scan_mode"
                value="active"
                checked={scanMode === 'active'}
                onChange={() => setScanMode('active')}
                disabled={!canActive}
              />
              <div>
                <p className="font-medium text-gray-900">Active Scan</p>
                <p className="text-xs text-gray-500">authorized/admin role</p>
              </div>
            </label>
            <label className={`flex items-center gap-3 p-4 rounded-2xl border-2 transition-all ${isAdmin ? 'border-gray-200 cursor-pointer hover:border-blue-500' : 'border-gray-100 opacity-50 cursor-not-allowed'}`}>
              <input
                type="radio"
                name="scan_mode"
                value="full"
                checked={scanMode === 'full'}
                onChange={() => setScanMode('full')}
                disabled={!isAdmin}
              />
              <div>
                <p className="font-medium text-gray-900">Full Scan</p>
                <p className="text-xs text-gray-500">admin only</p>
              </div>
            </label>
          </div>

          {error ? <p className="text-sm text-red-600">{error}</p> : null}
        </form>
      </div>

      <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scans</h3>
        {loadingRecent ? <p className="text-sm text-gray-500">Loading scans...</p> : null}
        {!loadingRecent && recentScans.length === 0 ? <p className="text-sm text-gray-500">No scans yet.</p> : null}
        <div className="space-y-2">
          {recentScans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => navigate(`/scan/${scan.id}`)}
              className="flex items-center justify-between p-4 rounded-2xl bg-gray-50/50 hover:bg-gray-100/50 transition-all cursor-pointer group"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-gray-100 to-gray-200 flex items-center justify-center group-hover:from-blue-100 group-hover:to-purple-100 transition-all">
                  {scan.target.includes('.') ? (
                    <Globe className="w-5 h-5 text-gray-600 group-hover:text-blue-600 transition-colors" />
                  ) : (
                    <Server className="w-5 h-5 text-gray-600 group-hover:text-blue-600 transition-colors" />
                  )}
                </div>
                <div>
                  <p className="font-medium text-gray-900">{scan.target}</p>
                  <div className="flex items-center gap-2 text-sm text-gray-500">
                    <Clock className="w-3 h-3" />
                    {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown'}
                  </div>
                </div>
              </div>
              <span className={`px-3 py-1 rounded-lg text-sm font-medium ${scan.status === 'completed' ? 'bg-green-100 text-green-700' : scan.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>
                {scan.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
