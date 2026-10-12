import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router';
import { AlertTriangle, Clock, Download, Globe, Shield } from 'lucide-react';

import { Finding, getFindingsByScanId } from '../../../api/findings';
import { getScanById, ScanDetailsResponse } from '../../../api/scans';
import { handleApiError } from '../../../utils/errorHandler';
import { formatDateTime } from '../../../utils/date';

function statusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return 'bg-green-100 text-green-700 border border-green-200';
    case 'in_progress':
    case 'running':
      return 'bg-blue-100 text-blue-700 border border-blue-200';
    case 'scheduled':
      return 'bg-purple-100 text-purple-700 border border-purple-200';
    case 'failed':
      return 'bg-red-100 text-red-700 border border-red-200';
    case 'queued':
    case 'pending':
      return 'bg-amber-100 text-amber-700 border border-amber-200';
    default:
      return 'bg-gray-100 text-gray-700 border border-gray-200';
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
    let timerId: ReturnType<typeof setTimeout> | null = null;

    const fetchScanData = async (isInitial = false) => {
      if (isInitial) {
        setLoading(true);
        setError(null);
        setFindingsLoading(true);
        setFindingsError(null);
      }

      try {
        const [scanResult, findingsResult] = await Promise.allSettled([
          getScanById(scanId),
          getFindingsByScanId(scanId, { limit: 100 }),
        ]);

        if (!mounted) return;

        let currentStatus = '';
        if (scanResult.status === 'fulfilled') {
          setScan(scanResult.value);
          currentStatus = scanResult.value?.status || '';
        } else if (isInitial) {
          setError('Failed to fetch scan details');
          handleApiError(scanResult.reason);
        }

        if (findingsResult.status === 'fulfilled') {
          const rawFindings = Array.isArray(findingsResult.value?.findings) ? findingsResult.value.findings : [];
          const filtered = rawFindings.filter((finding) => String(finding?.scan?.id || '') === scanId);
          setFindings(filtered.length ? filtered : rawFindings);
        } else if (isInitial) {
          setFindingsError('Failed to fetch scan findings');
          handleApiError(findingsResult.reason);
        }

        if (isInitial) {
          setLoading(false);
          setFindingsLoading(false);
        }

        // If scan is still active (scheduled, queued, or running), poll every 3 seconds
        const activeStatuses = ['scheduled', 'queued', 'pending', 'in_progress', 'running'];
        if (activeStatuses.includes(currentStatus.toLowerCase())) {
          timerId = setTimeout(() => {
            if (mounted) void fetchScanData(false);
          }, 3000);
        }
      } catch {
        if (mounted && isInitial) {
          setError('Failed to load scan');
          setLoading(false);
          setFindingsLoading(false);
        }
      }
    };

    void fetchScanData(true);

    return () => {
      mounted = false;
      if (timerId) clearTimeout(timerId);
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

  const isScheduled = scan.status.toLowerCase() === 'scheduled';
  const scheduledTimeDisplay = scan.scheduledAt || scan.estimatedStartTime;

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
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-500 to-blue-600 text-white hover:shadow-lg transition-all cursor-pointer"
        >
          <Download className="w-4 h-4" />
          Export
        </button>
      </div>

      {isScheduled ? (
        <div className="bg-purple-50 border border-purple-200 rounded-2xl p-4 text-sm text-purple-900 flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-purple-600 shrink-0" />
            <div>
              <p className="font-semibold text-purple-900">Scan Scheduled</p>
              <p className="text-purple-700 text-xs mt-0.5">
                This scan is scheduled to start at <span className="font-semibold">{formatDateTime(scheduledTimeDisplay)}</span>. It will automatically begin and update live when the scheduled time arrives.
              </p>
            </div>
          </div>
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100 shadow-sm">
          <p className="text-sm text-gray-500">Progress</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.progress}%</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100 shadow-sm">
          <p className="text-sm text-gray-500">Findings</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.findings.total}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100 shadow-sm">
          <p className="text-sm text-gray-500">Duration</p>
          <p className="text-2xl font-semibold text-gray-900">{durationLabel}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100 shadow-sm">
          <p className="text-sm text-gray-500">{isScheduled ? 'Scheduled For' : 'Started'}</p>
          <p className="text-lg font-semibold text-gray-900 truncate">
            {isScheduled ? formatDateTime(scheduledTimeDisplay) : (scan.startedAt ? formatDateTime(scan.startedAt) : '—')}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Target Information</h3>
          <div className="space-y-3 text-sm text-gray-700">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-500" />
              Scan ID: <span className="font-mono text-xs">{scan.id}</span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-500" />
              Target: <span className="font-semibold text-gray-900">{scan.target}</span>
            </div>
            {isScheduled ? (
              <div className="flex items-center gap-2 text-purple-700">
                <Clock className="w-4 h-4 text-purple-600" />
                Scheduled Start: {formatDateTime(scheduledTimeDisplay)}
              </div>
            ) : null}
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" />
              Started: {scan.startedAt ? formatDateTime(scan.startedAt) : '—'}
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" />
              Completed: {scan.completedAt ? formatDateTime(scan.completedAt) : '—'}
            </div>
          </div>
        </div>

        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Findings Breakdown</h3>
          <div className="space-y-2 text-sm text-gray-700">
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span className="font-medium text-red-700">Critical</span>
              <span className="font-semibold">{scan.findings.critical}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span className="font-medium text-orange-700">High</span>
              <span className="font-semibold">{scan.findings.high}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span className="font-medium text-yellow-700">Medium</span>
              <span className="font-semibold">{scan.findings.medium}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
              <span className="font-medium text-green-700">Low</span>
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
          <div className="text-sm text-gray-600">
            {isScheduled ? 'Scan has not run yet. Findings will appear once execution begins.' : 'No findings reported for this scan.'}
          </div>
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
                      {finding.discoveredAt ? formatDateTime(finding.discoveredAt) : '—'}
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
