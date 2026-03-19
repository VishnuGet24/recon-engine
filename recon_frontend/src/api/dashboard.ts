import { apiRequest } from './client';

export type DashboardMetrics = {
  totalAssets: { value: number; change: { percentage: number; direction: 'increase' | 'decrease' | 'neutral'; timeframe: string } };
  criticalFindings: { value: number; change: { percentage: number; direction: 'increase' | 'decrease' | 'neutral'; timeframe: string } };
  riskScore: { value: number; maxValue: number; change: { value: number; direction: 'increase' | 'decrease' | 'neutral'; timeframe: string } };
  lastScan: { timestamp: string | null; relativeTime: string; nextScan: { timestamp: string | null; relativeTime: string } };
};

export type RiskTrendResponse = {
  data: { date: string; dateLabel: string; score: number }[];
  timeframe: string;
  granularity: string;
};

export type FindingsDistributionResponse = {
  distribution: { severity: 'critical' | 'high' | 'medium' | 'low'; count: number; color: string }[];
  total: number;
};

export type RecentScansResponse = {
  scans: {
    id: string;
    target: string;
    type: string;
    typeLabel: string;
    status: string;
    findings: number;
    startedAt: string | null;
    completedAt: string | null;
    duration: number | null;
    relativeTime: string;
  }[];
  total: number;
  limit: number;
  offset: number;
};

export function getDashboardMetrics() {
  return apiRequest<DashboardMetrics>('/dashboard/metrics');
}

export function getRiskTrend(params: { timeframe?: string; granularity?: string } = {}) {
  const query = new URLSearchParams();
  if (params.timeframe) query.set('timeframe', params.timeframe);
  if (params.granularity) query.set('granularity', params.granularity);
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiRequest<RiskTrendResponse>(`/dashboard/risk-trend${suffix}`);
}

export function getFindingsDistribution() {
  return apiRequest<FindingsDistributionResponse>('/dashboard/findings-distribution');
}

export function getRecentScans(params: { limit?: number; offset?: number } = {}) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set('limit', String(params.limit));
  if (params.offset != null) query.set('offset', String(params.offset));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiRequest<RecentScansResponse>(`/scans/recent${suffix}`);
}

export type RiskScoreResponse = {
  scan_id: number;
  overall_score: number;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  breakdown: { high: number; medium: number; low: number; info: number };
  top_risks: { title: string; severity: 'high' | 'medium' | 'low' | 'info' }[];
  generated_at?: string;
};

export function getRiskScore(params: { scanId: number | string }) {
  const query = new URLSearchParams();
  query.set('scan_id', String(params.scanId));
  return apiRequest<RiskScoreResponse>(`/dashboard/risk-score?${query.toString()}`);
}

export type SubdomainMapResponse = {
  scan_id: number;
  nodes: {
    id: string;
    type: 'root' | 'subdomain';
    riskLevel?: 'high' | 'medium' | 'low' | 'info';
    metadata?: {
      ipAddress?: string | null;
      technologies?: string[];
      openPorts?: number[];
      cloudProvider?: string | null;
      cdnProvider?: string | null;
      hostingProvider?: string | null;
    };
  }[];
  edges: { source: string; target: string }[];
};

export function getSubdomainMap(params: { scanId: number | string }) {
  const query = new URLSearchParams();
  query.set('scan_id', String(params.scanId));
  return apiRequest<SubdomainMapResponse>(`/dashboard/subdomain-map?${query.toString()}`);
}

export type ScanTimelineResponse = {
  scan_id: number;
  timeline: { stage: string; status: string; duration: number }[];
};

export function getScanTimeline(params: { scanId: number | string }) {
  const query = new URLSearchParams();
  query.set('scan_id', String(params.scanId));
  return apiRequest<ScanTimelineResponse>(`/dashboard/scan-timeline?${query.toString()}`);
}
