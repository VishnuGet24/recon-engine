import { apiDownload, apiRequest } from './client';

export type AssetsListResponse = {
  assets: {
    id: string;
    asset: string;
    type: string;
    typeLabel: string;
    riskLevel: string;
    findings: number;
    lastScan: { timestamp: string | null; relativeTime: string; scanId: string };
    status: string;
    metadata: { ipAddress?: string | null; cloudProvider?: string | null; region?: string | null; tags?: string[] };
    createdAt: string | null;
    updatedAt: string | null;
  }[];
  pagination: { total: number; page: number; limit: number; totalPages: number };
};

export type AssetStatsResponse = {
  total: number;
  active: number;
  inactive: number;
  atRisk: number;
  byType: { domains: number; ipAddresses: number; cloudResources: number; webApps: number };
  byRisk: { critical: number; high: number; medium: number; low: number };
};

export function getAssets(params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    query.set(key, String(value));
  }
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiRequest<AssetsListResponse>(`/assets${suffix}`);
}

export function getAssetStats() {
  return apiRequest<AssetStatsResponse>('/assets/stats');
}

export async function exportAssets(params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    query.set(key, String(value));
  }
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiDownload(`/assets/export${suffix}`);
}

