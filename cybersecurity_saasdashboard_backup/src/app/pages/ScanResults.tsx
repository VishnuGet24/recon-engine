import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router';
import { AlertTriangle, Clock, Download, Globe, Server, Shield } from 'lucide-react';

import { ApiError, getScanById, ScanRecord } from '../lib/api';

export default function ScanResults() {
  const { id } = useParams();
  const scanId = Number(id);

  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        const data = await getScanById(scanId);
        if (mounted) {
          setScan(data.scan);
        }
      } catch (err) {
        if (mounted) {
          if (err instanceof ApiError) {
            setError(err.message);
          } else {
            setError('Failed to fetch scan result');
          }
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
  }, [scanId]);

  const openPorts = useMemo(() => {
    const ports = (scan?.results?.port_scan as { open_ports?: number[] } | undefined)?.open_ports;
    return ports || [];
  }, [scan]);

  const resolvedIps = useMemo(() => {
    const ips = (scan?.results?.resolved_ips as string[] | undefined) || [];
    return ips;
  }, [scan]);

  if (loading) {
    return <div className="p-8 text-gray-600">Loading scan result...</div>;
  }

  if (error || !scan) {
    return <div className="p-8 text-red-600">{error || 'Scan not found'}</div>;
  }

  return (
    <div className="p-8">
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900 mb-2">Scan Results</h1>
          <p className="text-gray-500">
            Target: {scan.target} • Mode: {scan.scan_mode} • Status: {scan.status}
          </p>
        </div>
        <button
          onClick={() => window.print()}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-500 to-purple-600 text-white hover:shadow-lg transition-all"
        >
          <Download className="w-4 h-4" />
          Export
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Risk</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.overall_risk || 'N/A'}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Risk Score</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.risk_score ?? 'N/A'}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Confidence</p>
          <p className="text-2xl font-semibold text-gray-900">{scan.confidence_score ?? 'N/A'}</p>
        </div>
        <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-5 border border-gray-100">
          <p className="text-sm text-gray-500">Open Ports</p>
          <p className="text-2xl font-semibold text-gray-900">{openPorts.length}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Target Intelligence</h3>
          <div className="space-y-3 text-sm text-gray-700">
            <div className="flex items-center gap-2"><Shield className="w-4 h-4" />Scan ID: {scan.id}</div>
            <div className="flex items-center gap-2"><Globe className="w-4 h-4" />Target: {scan.target}</div>
            <div className="flex items-center gap-2"><Clock className="w-4 h-4" />Created: {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</div>
            <div className="flex items-center gap-2"><Clock className="w-4 h-4" />Completed: {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</div>
          </div>
          <div className="mt-4">
            <p className="text-sm font-medium text-gray-800 mb-2">Resolved IPs</p>
            {resolvedIps.length ? (
              <div className="flex flex-wrap gap-2">
                {resolvedIps.map((ip) => (
                  <span key={ip} className="px-2 py-1 bg-gray-100 rounded-lg text-xs">{ip}</span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No resolved IPs returned.</p>
            )}
          </div>
        </div>

        <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Port Findings</h3>
          {openPorts.length ? (
            <div className="space-y-2">
              {openPorts.map((port) => (
                <div key={port} className="flex items-center justify-between p-3 rounded-xl bg-gray-50">
                  <div className="flex items-center gap-2 text-gray-800">
                    <Server className="w-4 h-4" />
                    Port {port}
                  </div>
                  <span className="text-xs px-2 py-1 rounded bg-red-100 text-red-700">Open</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-green-50 text-green-700 text-sm">
              No open ports detected in scanned common ports.
            </div>
          )}
        </div>
      </div>

      <div className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-lg p-6 border border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Raw Scan JSON</h3>
        <div className="rounded-2xl bg-gray-950 text-gray-100 p-4 overflow-auto text-xs max-h-[460px]">
          <pre>{JSON.stringify(scan.results, null, 2)}</pre>
        </div>
        {scan.status === 'failed' ? (
          <div className="mt-4 flex items-center gap-2 text-sm text-red-600">
            <AlertTriangle className="w-4 h-4" />
            Scan execution failed. Check backend logs for details.
          </div>
        ) : null}
      </div>
    </div>
  );
}
