import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { Download, Eye, Globe, Network, Package, Play, Search, ShieldAlert } from 'lucide-react';

import { exportAssets, getAssetStats, getAssets } from '../../../api/assets';
import { handleApiError } from '../../../utils/errorHandler';

type AssetRow = {
  id: string;
  asset: string;
  typeLabel: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | string;
  findings: number;
  lastScanLabel: string;
  status: 'active' | 'inactive' | string;
  scanId: string;
};

function filenameFromContentDisposition(value: string | null) {
  if (!value) return null;
  const match = /filename=\"?([^\";]+)\"?/i.exec(value);
  return match?.[1] || null;
}

export default function AssetInventory() {
  const navigate = useNavigate();
  const [activeFilter, setActiveFilter] = useState<'all' | 'domains' | 'ips'>('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await getAssetStats();
        if (mounted) setStats(data);
      } catch (error) {
        if (mounted) handleApiError(error);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    let mounted = true;

    (async () => {
      setLoading(true);
      try {
        const data = await getAssets({
          page: 1,
          limit: 100,
          filter: activeFilter,
          search: search.trim() || undefined,
          sortBy: 'lastScan',
          sortOrder: 'desc',
        });

        if (!mounted) return;
        setAssets(
          data.assets.map((a) => ({
            id: a.id,
            asset: a.asset,
            typeLabel: a.typeLabel,
            riskLevel: a.riskLevel,
            findings: a.findings,
            lastScanLabel: a.lastScan?.timestamp ? new Date(a.lastScan.timestamp).toLocaleString() : a.lastScan?.relativeTime || '—',
            status: a.status,
            scanId: a.lastScan?.scanId || '',
          })),
        );
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setAssets([]);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    })();

    return () => {
      mounted = false;
    };
  }, [activeFilter, search]);

  const filters = useMemo(
    () => [
      { id: 'all' as const, label: 'All Assets', count: stats?.total ?? assets.length, icon: Package },
      { id: 'domains' as const, label: 'Domains', count: stats?.byType?.domains ?? 0, icon: Globe },
      { id: 'ips' as const, label: 'IP Addresses', count: stats?.byType?.ipAddresses ?? 0, icon: Network },
    ],
    [assets.length, stats],
  );

  const summaryCards = useMemo(
    () => [
      { label: 'Total Assets', value: String(stats?.total ?? 0), className: 'text-blue-600' },
      { label: 'Active', value: String(stats?.active ?? 0), className: 'text-green-600' },
      { label: 'Inactive', value: String(stats?.inactive ?? 0), className: 'text-gray-600' },
      { label: 'At Risk', value: String(stats?.atRisk ?? 0), className: 'text-red-600' },
    ],
    [stats],
  );

  const filteredAssets = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return assets;
    return assets.filter((a) => a.asset.toLowerCase().includes(q));
  }, [assets, search]);

  const getTypeIcon = (typeLabel: string) => {
    if (typeLabel.toLowerCase().includes('ip')) return { icon: Network, color: 'bg-purple-100 text-purple-700' };
    return { icon: Globe, color: 'bg-blue-100 text-blue-700' };
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical':
        return 'text-red-600';
      case 'high':
        return 'text-orange-600';
      case 'medium':
        return 'text-yellow-600';
      case 'low':
        return 'text-green-600';
      default:
        return 'text-gray-600';
    }
  };

  const getRiskDot = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical':
        return 'bg-red-500';
      case 'high':
        return 'bg-orange-500';
      case 'medium':
        return 'bg-yellow-500';
      case 'low':
        return 'bg-green-500';
      default:
        return 'bg-gray-500';
    }
  };

  const onExport = async () => {
    try {
      const response = await exportAssets({ format: 'csv', filter: activeFilter });
      const blob = await response.blob();
      const filename = filenameFromContentDisposition(response.headers.get('content-disposition')) || 'assets-export.csv';

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      handleApiError(error);
    }
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Asset Inventory</h1>
          <p className="text-gray-500 mt-1">Discovered assets and their latest scan posture</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Search assets…"
            />
          </div>
          <button type="button" onClick={() => void onExport()} className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-xl hover:bg-blue-600">
            <Download className="w-5 h-5" />
            <span>Export</span>
          </button>
        </div>
      </div>

      <div className="flex items-center gap-4 mb-6 overflow-x-auto pb-2">
        {filters.map((filter) => {
          const Icon = filter.icon;
          const selected = activeFilter === filter.id;
          return (
            <button
              key={filter.id}
              type="button"
              onClick={() => setActiveFilter(filter.id)}
              className={`
                flex items-center gap-2 px-4 py-2 rounded-xl whitespace-nowrap transition-all
                ${selected ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/30' : 'bg-white text-gray-700 hover:bg-gray-50 border border-gray-200'}
              `}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{filter.label}</span>
              <span className={`
                px-2 py-0.5 rounded-full text-xs
                ${selected ? 'bg-white/20 text-white' : 'bg-gray-100 text-gray-600'}
              `}>
                {filter.count}
              </span>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {summaryCards.map((stat, index) => (
          <div key={index} className="bg-white rounded-2xl p-4 shadow-sm">
            <p className="text-sm text-gray-500 mb-1">{stat.label}</p>
            <p className={`text-2xl font-semibold ${stat.className}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-2xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Asset</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Type</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Risk Level</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Findings</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Last Scan</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Status</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-500">
                    Loading assets…
                  </td>
                </tr>
              ) : null}
              {!loading ? (
                filteredAssets.map((asset, index) => {
                  const typeInfo = getTypeIcon(asset.typeLabel);
                  const TypeIcon = typeInfo.icon;

                  return (
                    <tr key={asset.id} className={`border-b border-gray-100 hover:bg-blue-50 transition-colors ${index % 2 === 0 ? 'bg-white' : 'bg-gray-50/50'}`}>
                      <td className="py-4 px-6">
                        <span className="font-semibold text-gray-900">{asset.asset}</span>
                      </td>
                      <td className="py-4 px-6">
                        <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full ${typeInfo.color}`}>
                          <TypeIcon className="w-4 h-4" />
                          <span className="text-xs font-medium">{asset.typeLabel}</span>
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${getRiskDot(asset.riskLevel)}`}></div>
                          <span className={`font-medium ${getRiskColor(asset.riskLevel)}`}>{asset.riskLevel}</span>
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        <span className="font-semibold text-gray-900">{asset.findings}</span>
                      </td>
                      <td className="py-4 px-6 text-gray-500">{asset.lastScanLabel}</td>
                      <td className="py-4 px-6">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${asset.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'}`}>
                          {asset.status}
                        </span>
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => navigate(`/new-scan?target=${encodeURIComponent(asset.asset)}`)}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            disabled={!asset.scanId}
                            onClick={() => navigate(`/scan/${asset.scanId}`)}
                            className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-50"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : null}

              {!loading && filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-500">
                    <div className="flex items-center justify-center gap-2">
                      <ShieldAlert className="h-4 w-4" />
                      No assets matched the current filters.
                    </div>
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

