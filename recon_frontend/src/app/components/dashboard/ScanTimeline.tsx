import { ResponsiveContainer, BarChart, Bar, CartesianGrid, Cell, Tooltip, XAxis, YAxis } from 'recharts';

import type { ScanTimelineResponse } from '../../../api/dashboard';

function statusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return '#22c55e';
    case 'failed':
      return '#ef4444';
    case 'running':
      return '#3b82f6';
    default:
      return '#94a3b8';
  }
}

export default function ScanTimeline({ data, loading }: { data: ScanTimelineResponse | null; loading?: boolean }) {
  const timeline = data?.timeline || [];
  const chartData = timeline.map((item) => ({
    stage: item.stage,
    duration: item.duration,
    status: item.status,
    fill: statusColor(item.status),
  }));

  return (
    <div className="bg-white rounded-2xl p-6 shadow-sm">
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Scan Timeline</h3>
        <p className="text-sm text-gray-500">Module execution order and approximate durations</p>
      </div>

      <div className="h-80">
        {loading ? (
          <div className="h-full flex items-center justify-center text-sm text-gray-500">Loading timeline…</div>
        ) : chartData.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis type="number" stroke="#9ca3af" allowDecimals={false} />
              <YAxis type="category" dataKey="stage" stroke="#9ca3af" width={160} />
              <Tooltip />
              <Bar dataKey="duration" radius={[0, 8, 8, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.stage} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-gray-500">No module timeline available for this scan.</div>
        )}
      </div>

      <div className="mt-3 text-xs text-gray-500">Duration unit: seconds (best-effort approximation).</div>
    </div>
  );
}

