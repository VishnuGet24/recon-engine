import { apiRequest } from './client';

export type Finding = {
  id: string;
  severity: string;
  title: string;
  description: string;
  status: string;
  discoveredAt: string | null;
  asset?: { id?: string; name?: string; type?: string } | null;
  scan?: { id?: string; timestamp?: string | null } | null;
};

export type FindingsListResponse = {
  findings: Finding[];
  pagination?: { total: number; page: number; limit: number; totalPages: number };
};

export function getFindingsByScanId(scanId: string, params: { page?: number; limit?: number } = {}) {
  const query = new URLSearchParams();
  query.set('scan_id', scanId);
  if (params.page != null) query.set('page', String(params.page));
  if (params.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiRequest<FindingsListResponse>(`/findings${suffix}`);
}

