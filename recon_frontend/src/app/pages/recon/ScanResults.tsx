import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router';
import { AlertTriangle, Clock, Download, Globe, Shield } from 'lucide-react';

import { Finding, getFindingsByScanId } from '../../../api/findings';
import { getScanById, ScanDetailsResponse } from '../../../api/scans';
import { handleApiError } from '../../../utils/errorHandler';

function statusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return 'bg-green-100 text-green-700';
    case 'in_progress':
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

function severityBadge(severity: string) {
  const value = (severity || '').toLowerCase();
  switch (value) {
    case 'critical':
      return 'bg-red-100 text-red-700';
    case 'high':
      return 'bg-orange-100 text-orange-700';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700';
    case 'low':
      return 'bg-green-100 text-green-700';
    default:
      return 'bg-gray-100 text-gray-700';
  }
}

export default function ScanResults() {
  const { id } = useParams();
  const scanId = String(id || '');
  const [scan, setScan] = useState<ScanDetailsResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);
    setFindingsLoading(true);
    setFindingsError(null);
    setFindings([]);

    (async () => {
      const [scanResult, findingsResult] = await Promise.allSettled([
        getScanById(scanId),
        getFindingsByScanId(scanId, { limit: 100 }),
      ]);

      if (!mounted) return;

      if (scanResult.status === 'fulfilled') {
        setScan(scanResult.value);
      } else {
        setError('Failed to fetch scan details');
        handleApiError(scanResult.reason);
      }

      if (findingsResult.status === 'fulfilled') {
        const rawFindings = Array.isArray(findingsResult.value?.findings) ? findingsResult.value.findings : [];
        const filtered = rawFindings.filter((finding) => String(finding?.scan?.id || '') === scanId);
        setFindings(filtered.length ? filtered : rawFindings);
      } else {
        setFindingsError('Failed to fetch scan findings');
        handleApiError(findingsResult.reason);
      }

      setLoading(false);
      setFindingsLoading(false);
    })();

    return () => {
      mounted = false;
    };
  }, [scanId]);

  const durationLabel = useMemo(() => {
    if (!scan?.duration) return '—';
    const minutes = Math.round(scan.duration / 60);
    return `${minutes} min`;
  }, [scan]);

  if (loading) {
    return <div className="p-8 text-gray-600">Loading scan…</div>;
  }

  if (error || !scan) {
    return <div className="p-8 text-red-600">{error || 'Scan not found'}</div>;
  }

  return (
    <div className="p-8">
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900 mb-2">Scan Details</h1>
          <p className="text-gray-500">
            Target: {scan.target} • Type: {scan.scanType} • Status:{' '}
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${statusColor(scan.status)}`}>{scan.status}</span>
          </p>
        </div>
        <button
          type="button"
          onClick={() => window.print()}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-500 to-blue-600 text-white hover:shadow-lg transition-all"
        >
          <Download className="w-4 h-4" />
          Export
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Progress</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.progress}%</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Findings</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.findings.total}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Duration</p>
          <p className="text-2xl font-semibold text-gray-900">{durationLabel}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Started</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Target</h3>
          <div className="space-y-3 text-sm text-gray-700">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Scan ID: {scan.id}
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4" />
              Target: {scan.target}
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Started: {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Completed: {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : '—'}
            </div>
          </div>
        </div>

        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Findings Breakdown</h3>
          <div className="space-y-2 text-sm text-gray-700">
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span>Critical</span>
              <span className="font-semibold">{scan.findings.critical}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span>High</span>
              <span className="font-semibold">{scan.findings.high}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span>Medium</span>
              <span className="font-semibold">{scan.findings.medium}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span>Low</span>
              <span className="font-semibold">{scan.findings.low}</span>
            </div>
          </div>
        </div>
      </div>

      {scan.status === 'failed' ? (
        <div className="bg-red-50 border border-red-200 rounded-2xl p-4 text-sm text-red-700 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          Scan execution failed. Check backend logs for details.
        </div>
      ) : null}

      <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Findings</h3>
          <div className="text-sm text-gray-500">{findingsLoading ? 'Loading…' : `${findings.length} items`}</div>
        </div>

        {findingsError ? <div className="text-sm text-red-600 mb-3">{findingsError}</div> : null}
        {!findingsLoading && findings.length === 0 ? (
          <div className="text-sm text-gray-600">No findings reported for this scan.</div>
        ) : null}

        {findings.length ? (
          <div className="overflow-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-gray-600 border-b border-gray-200">
                  <th className="py-3 pr-4 font-medium">Severity</th>
                  <th className="py-3 pr-4 font-medium">Title</th>
                  <th className="py-3 pr-4 font-medium">Asset Name</th>
                  <th className="py-3 pr-4 font-medium">Description</th>
                  <th className="py-3 pr-4 font-medium">Status</th>
                  <th className="py-3 pr-4 font-medium">Discovered At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {findings.map((finding) => (
                  <tr key={finding.id} className="text-gray-800">
                    <td className="py-3 pr-4 align-top">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${severityBadge(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-3 pr-4 align-top font-medium text-gray-900">{finding.title}</td>
                    <td className="py-3 pr-4 align-top">{finding.asset?.name || '—'}</td>
                    <td className="py-3 pr-4 align-top text-gray-700">{finding.description}</td>
                    <td className="py-3 pr-4 align-top">{finding.status}</td>
                    <td className="py-3 pr-4 align-top whitespace-nowrap">
                      {finding.discoveredAt ? new Date(finding.discoveredAt).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </div>
  );
}
