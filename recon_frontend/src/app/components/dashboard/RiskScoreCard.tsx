import { ResponsiveContainer, RadialBarChart, RadialBar, PolarAngleAxis, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';

import type { RiskScoreResponse } from '../../../api/dashboard';

function riskColor(level: RiskScoreResponse['risk_level'] | null | undefined) {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return { text: 'text-red-700', bg: 'bg-red-50', chart: '#ef4444' };
    case 'high':
      return { text: 'text-orange-700', bg: 'bg-orange-50', chart: '#f97316' };
    case 'medium':
      return { text: 'text-yellow-700', bg: 'bg-yellow-50', chart: '#eab308' };
    default:
      return { text: 'text-green-700', bg: 'bg-green-50', chart: '#22c55e' };
  }
}

export default function RiskScoreCard({ data, loading }: { data: RiskScoreResponse | null; loading?: boolean }) {
  const score = data?.overall_score ?? 0;
  const level = data?.risk_level ?? 'Low';
  const breakdown = data?.breakdown ?? { high: 0, medium: 0, low: 0, info: 0 };
  const topRisks = data?.top_risks ?? [];

  const ui = riskColor(level);
  const gaugeValue = Math.max(0, Math.min(score, 100));

  const gaugeData = [{ name: 'risk', value: gaugeValue, fill: ui.chart }];
  const breakdownData = [
    { name: 'High', value: breakdown.high, fill: '#f97316' },
    { name: 'Medium', value: breakdown.medium, fill: '#eab308' },
    { name: 'Low', value: breakdown.low, fill: '#22c55e' },
    { name: 'Info', value: breakdown.info, fill: '#94a3b8' },
  ];

  return (
    <div className="bg-white rounded-2xl p-6 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">Risk Score</h3>
          <p className="text-sm text-gray-500">Computed from persisted findings severity counts</p>
        </div>
        <div className={`px-3 py-1 rounded-full text-xs font-semibold ${ui.bg} ${ui.text}`}>
          {loading ? 'Loading…' : level}
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                data={gaugeData}
                innerRadius="70%"
                outerRadius="100%"
                startAngle={180}
                endAngle={0}
                cx="50%"
                cy="70%"
              >
                <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                <RadialBar dataKey="value" cornerRadius={10} background={{ fill: '#e5e7eb' }} />
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-[-3.5rem] text-center">
            <div className="text-3xl font-semibold text-gray-900">{score}</div>
            <div className="text-xs text-gray-500">Score (gauge capped at 100)</div>
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="mb-2">
            <h4 className="text-sm font-semibold text-gray-900">Severity breakdown</h4>
            <p className="text-xs text-gray-500">High/Medium/Low contribute to the score</p>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={breakdownData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="name" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {breakdownData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="mb-2">
            <h4 className="text-sm font-semibold text-gray-900">Top risks</h4>
            <p className="text-xs text-gray-500">High-impact findings (deduped)</p>
          </div>
          <div className="space-y-2">
            {topRisks.length ? (
              topRisks.map((risk) => (
                <div key={risk.title} className="flex items-start justify-between gap-3 rounded-xl border border-gray-100 px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-gray-900">{risk.title}</div>
                    <div className="text-xs text-gray-500">{risk.severity}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="rounded-xl border border-dashed border-gray-200 p-4 text-sm text-gray-500">
                {loading ? 'Loading risks…' : 'No findings for this scan yet.'}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

