import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { AlertTriangle, ChevronRight, Clock, Package, Shield, TrendingDown, TrendingUp } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { getDashboardMetrics, getFindingsDistribution, getRecentScans, getRiskTrend } from '../../../api/dashboard';
import { handleApiError } from '../../../utils/errorHandler';

function getStatusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return 'bg-green-100 text-green-700';
    case 'in_progress':
    case 'running':
      return 'bg-blue-100 text-blue-700';
    case 'failed':
      return 'bg-red-100 text-red-700';
    case 'queued':
    case 'pending':
      return 'bg-gray-100 text-gray-700';
    default:
      return 'bg-gray-100 text-gray-700';
  }
}

function getTypeColor(type: string) {
  if (type === 'full_scan') return 'bg-blue-100 text-blue-700';
  if (type === 'custom_scan') return 'bg-gray-100 text-gray-700';
  return 'bg-purple-100 text-purple-700';
}

export default function ReconDashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<any>(null);
  const [riskTrend, setRiskTrend] = useState<{ dateLabel: string; score: number }[]>([]);
  const [distribution, setDistribution] = useState<{ severity: string; count: number; color: string }[]>([]);
  const [recentScans, setRecentScans] = useState<any[]>([]);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoading(true);
      try {
        const [m, trend, dist, recent] = await Promise.all([
          getDashboardMetrics(),
          getRiskTrend({ timeframe: '30d' }),
          getFindingsDistribution(),
          getRecentScans({ limit: 10, offset: 0 }),
        ]);
        if (!mounted) return;
        setMetrics(m);
        setRiskTrend(trend.data.map((p) => ({ dateLabel: p.dateLabel, score: p.score })));
        setDistribution(dist.distribution);
        setRecentScans(recent.scans);
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setMetrics(null);
          setRiskTrend([]);
          setDistribution([]);
          setRecentScans([]);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    void load();
    const interval = window.setInterval(load, 30000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const metricCards = useMemo(() => {
    const lastScanTs = metrics?.lastScan?.timestamp ? new Date(metrics.lastScan.timestamp).toLocaleString() : 'No scans yet';
    const riskValue = typeof metrics?.riskScore?.value === 'number' ? metrics.riskScore.value.toFixed(1) : '0.0';

    return [
      {
        title: 'Total Assets',
        value: String(metrics?.totalAssets?.value ?? 0),
        change: loading ? 'Loading assets...' : metrics?.totalAssets?.change?.timeframe ?? '',
        changeType: (metrics?.totalAssets?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: Package,
        iconBg: 'from-blue-400 to-blue-600',
      },
      {
        title: 'Critical Findings',
        value: String(metrics?.criticalFindings?.value ?? 0),
        change: loading ? 'Loading findings...' : metrics?.criticalFindings?.change?.timeframe ?? '',
        changeType: (metrics?.criticalFindings?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: AlertTriangle,
        iconBg: 'from-red-400 to-red-600',
      },
      {
        title: 'Risk Score',
        value: `${riskValue}/10`,
        change: loading ? 'Calculating...' : metrics?.riskScore?.change?.timeframe ?? '',
        changeType: (metrics?.riskScore?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: Shield,
        iconBg: 'from-orange-400 to-orange-600',
      },
      {
        title: 'Last Scan',
        value: lastScanTs,
        change: metrics?.lastScan?.relativeTime || '',
        changeType: 'neutral' as const,
        icon: Clock,
        iconBg: 'from-green-400 to-green-600',
      },
    ];
  }, [loading, metrics]);

  const riskScoreData = useMemo(() => riskTrend.map((p) => ({ date: p.dateLabel, score: p.score })), [riskTrend]);

  const findingsData = useMemo(
    () =>
      distribution.map((d) => ({
        name: d.severity[0].toUpperCase() + d.severity.slice(1),
        value: d.count,
        fill: d.color,
      })),
    [distribution],
  );

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Reconnaissance Dashboard</h1>
        <p className="text-gray-500 mt-1">Live view of dashboard metrics, trends, and scan activity</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {metricCards.map((card, index) => {
          const Icon = card.icon;
          return (
            <div key={index} className="bg-white rounded-2xl p-6 shadow-sm hover:shadow-lg hover:scale-[1.02] transition-all">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <p className="text-sm text-gray-500 mb-1">{card.title}</p>
                  <p className="text-2xl font-semibold text-gray-900">{card.value}</p>
                </div>
                <div className={`w-12 h-12 rounded-full bg-gradient-to-br ${card.iconBg} flex items-center justify-center`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm">
                {card.changeType === 'increase' && <TrendingUp className="w-4 h-4 text-green-500" />}
                {card.changeType === 'decrease' && <TrendingDown className="w-4 h-4 text-red-500" />}
                <span className="text-gray-600">{card.change}</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
        <div className="lg:col-span-3 bg-white rounded-2xl p-6 shadow-sm">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Risk Score Trend</h3>
            <p className="text-sm text-gray-500">Time-series from the backend</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={riskScoreData}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="date" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip />
              <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={3} fill="url(#colorScore)" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-2 bg-white rounded-2xl p-6 shadow-sm">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Finding Distribution</h3>
            <p className="text-sm text-gray-500">Counts by severity</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={findingsData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip />
              <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                {findingsData.map((entry, index) => (
                  <Cell key={`bar-${index}`} fill={entry.fill} radius={[8, 8, 0, 0]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white rounded-2xl p-6 shadow-sm">
        <div className="mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Recent Scans</h3>
          <p className="text-sm text-gray-500">Newest scan activity</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Scan Target</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Type</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Status</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Findings</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Date</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan) => (
                <tr key={scan.id} className="border-b border-gray-100 hover:bg-blue-50 transition-colors">
                  <td className="py-4 px-4">
                    <span className="font-semibold text-gray-900">{scan.target}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getTypeColor(scan.type)}`}>{scan.typeLabel}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(scan.status || '')}`}>{scan.status}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`font-semibold ${scan.findings > 4 ? 'text-red-600' : 'text-gray-900'}`}>{scan.findings}</span>
                  </td>
                  <td className="py-4 px-4 text-gray-500">{scan.startedAt ? new Date(scan.startedAt).toLocaleString() : 'Unknown'}</td>
                  <td className="py-4 px-4">
                    <button type="button" onClick={() => navigate(`/scan/${scan.id}`)} className="flex items-center gap-1 text-blue-600 hover:text-blue-700">
                      <span className="text-sm">View</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && recentScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-gray-500">
                    No scan data is available yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

