import { useEffect, useMemo, useState } from 'react';

import { getRecentScans, getRiskScore, getScanTimeline, getSubdomainMap, type RecentScansResponse, type RiskScoreResponse, type ScanTimelineResponse, type SubdomainMapResponse } from '../../../api/dashboard';
import { handleApiError } from '../../../utils/errorHandler';
import RiskScoreCard from '../../components/dashboard/RiskScoreCard';
import SubdomainGraph from '../../components/dashboard/SubdomainGraph';
import ScanTimeline from '../../components/dashboard/ScanTimeline';

export default function Dashboard() {
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const [recentScans, setRecentScans] = useState<RecentScansResponse['scans']>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');

  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [subdomainMap, setSubdomainMap] = useState<SubdomainMapResponse | null>(null);
  const [scanTimeline, setScanTimeline] = useState<ScanTimelineResponse | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoadingScans(true);
      try {
        const recent = await getRecentScans({ limit: 25, offset: 0 });
        if (!mounted) return;
        setRecentScans(recent.scans || []);
        if (recent.scans?.length) {
          setSelectedScanId((prev) => prev || String(recent.scans[0].id));
        }
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setRecentScans([]);
        }
      } finally {
        if (mounted) setLoadingScans(false);
      }
    };

    void load();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    if (!selectedScanId) return () => {};

    const loadDetails = async () => {
      setLoadingDetails(true);
      try {
        const scanId = selectedScanId;
        const [risk, graph, timeline] = await Promise.all([
          getRiskScore({ scanId }),
          getSubdomainMap({ scanId }),
          getScanTimeline({ scanId }),
        ]);
        if (!mounted) return;
        setRiskScore(risk);
        setSubdomainMap(graph);
        setScanTimeline(timeline);
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setRiskScore(null);
          setSubdomainMap(null);
          setScanTimeline(null);
        }
      } finally {
        if (mounted) setLoadingDetails(false);
      }
    };

    void loadDetails();
    return () => {
      mounted = false;
    };
  }, [selectedScanId]);

  const selectedScan = useMemo(() => recentScans.find((s) => String(s.id) === String(selectedScanId)) || null, [recentScans, selectedScanId]);

  return (
    <div className="p-8">
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">Attack Surface Dashboard</h1>
          <p className="text-gray-500 mt-1">Risk score, subdomain relationships, and scan execution timeline</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-sm text-gray-500">
            {loadingScans ? 'Loading scans…' : recentScans.length ? `${recentScans.length} recent scans` : 'No scans available'}
          </div>
          <select
            className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm"
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            disabled={!recentScans.length}
          >
            {recentScans.map((scan) => (
              <option key={scan.id} value={String(scan.id)}>
                #{scan.id} · {scan.target} · {scan.typeLabel} · {scan.status}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!loadingScans && !recentScans.length ? (
        <div className="bg-white rounded-2xl p-8 shadow-sm text-center">
          <div className="text-lg font-semibold text-gray-900">No scan data yet</div>
          <div className="mt-2 text-sm text-gray-500">Run a scan first, then come back to visualize risk score and relationships.</div>
        </div>
      ) : (
        <div className="space-y-6">
          <RiskScoreCard data={riskScore} loading={loadingDetails} />
          <SubdomainGraph data={subdomainMap} loading={loadingDetails} />
          <ScanTimeline data={scanTimeline} loading={loadingDetails} />

          {selectedScan ? (
            <div className="text-xs text-gray-500">
              Viewing scan #{selectedScan.id} · target <span className="font-medium text-gray-700">{selectedScan.target}</span> · status{' '}
              <span className="font-medium text-gray-700">{selectedScan.status}</span>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
