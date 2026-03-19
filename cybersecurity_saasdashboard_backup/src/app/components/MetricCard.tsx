import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string;
  change: string;
  trend: 'up' | 'down';
  icon: LucideIcon;
  iconColor: string;
}

export default function MetricCard({ title, value, change, trend, icon: Icon, iconColor }: MetricCardProps) {
  const isPositive = trend === 'down' && (title.includes('Vulnerabilities') || title.includes('CVSS'));
  const changeColor = isPositive || (trend === 'up' && !title.includes('Vulnerabilities'))
    ? 'text-green-600 bg-green-50'
    : 'text-red-600 bg-red-50';

  return (
    <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-all">
      <div className="flex items-start justify-between mb-4">
        <div className={`w-12 h-12 rounded-2xl bg-gradient-to-br ${iconColor} flex items-center justify-center shadow-md`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        <div className={`flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium ${changeColor}`}>
          {trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {change}
        </div>
      </div>
      <h3 className="text-sm text-gray-600 mb-1">{title}</h3>
      <p className="text-3xl font-semibold text-gray-900">{value}</p>
    </div>
  );
}
