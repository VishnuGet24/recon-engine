import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { Activity, AlertTriangle, Shield, TrendingUp } from 'lucide-react';

import MetricCard from '../components/MetricCard';
import CircularProgress from '../components/CircularProgress';
import { listScans, ScanRecord } from '../lib/api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        const data = await listScans();
        if (mounted) {
          setScans(data.scans);
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  const metrics = useMemo(() => {
    const total = scans.length;
    const critical = scans.filter((scan) => scan.overall_risk === 'Critical').length;
    const avgRisk = scans.length
      ? (scans.reduce((acc, item) => acc + (item.risk_score || 0), 0) / scans.length).toFixed(1)
      : '0.0';
    const monitoredAssets = new Set(scans.map((scan) => scan.target)).size;

    return { total, critical, avgRisk, monitoredAssets };
  }, [scans]);

  const completedPct = useMemo(() => {
    if (!scans.length) return 0;
    const completed = scans.filter((scan) => scan.status === 'completed').length;
    return Math.round((completed / scans.length) * 100);
  }, [scans]);

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900 mb-2">Security Dashboard</h1>
        <p className="text-gray-500">Monitor your attack surface and vulnerability landscape</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <MetricCard
          title="Total Scans"
          value={String(metrics.total)}
          change={loading ? '...' : '+0%'}
          trend="up"
          icon={Shield}
          iconColor="from-blue-500 to-blue-600"
        />
        <MetricCard
          title="Critical Vulnerabilities"
          value={String(metrics.critical)}
          change={loading ? '...' : 'live'}
          trend="down"
          icon={AlertTriangle}
          iconColor="from-red-500 to-red-600"
        />
        <MetricCard
          title="Average CVSS Score"
          value={metrics.avgRisk}
          change={loading ? '...' : 'live'}
          trend="down"
          icon={Activity}
          iconColor="from-orange-500 to-orange-600"
        />
        <MetricCard
          title="Assets Monitored"
          value={String(metrics.monitoredAssets)}
          change={loading ? '...' : 'live'}
          trend="up"
          icon={TrendingUp}
          iconColor="from-purple-500 to-purple-600"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Execution Health</h3>
          <div className="flex flex-col items-center">
            <CircularProgress value={completedPct} size={180} strokeWidth={12} />
            <p className="mt-4 text-sm text-gray-600">{completedPct}% completed scans</p>
            <p className="text-xs text-gray-500 mt-1">Auto-updated from DB</p>
          </div>
        </div>

        <div className="lg:col-span-2 bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scan Activity</h3>
          <div className="space-y-3">
            {scans.slice(0, 10).map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-4 rounded-2xl bg-gray-50/50 hover:bg-gray-100/50 transition-all cursor-pointer"
                onClick={() => navigate(`/scan/${scan.id}`)}
              >
                <div>
                  <p className="font-medium text-gray-900">{scan.target}</p>
                  <p className="text-sm text-gray-500">
                    {scan.scan_mode} • {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-600">Risk: {scan.overall_risk || 'N/A'}</span>
                  <span className={`px-3 py-1 rounded-lg text-sm font-medium ${scan.status === 'completed' ? 'bg-green-100 text-green-700' : scan.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>
                    {scan.status}
                  </span>
                </div>
              </div>
            ))}
            {!loading && scans.length === 0 ? <p className="text-sm text-gray-500">No scans available.</p> : null}
          </div>
        </div>
      </div>
    </div>
  );
}
