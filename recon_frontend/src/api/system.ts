import { apiRequest } from './client';

export type SystemHealthResponse = {
  status: 'operational' | 'degraded' | 'down';
  services: {
    scanner: { status: string; uptime: number; activeScans: number; queuedScans: number };
    database: { status: string; responseTime: number; connections: number };
    api: { status: string; responseTime: number; requestsPerMinute: number };
  };
  lastUpdated: string;
};

export function getSystemHealth() {
  return apiRequest<SystemHealthResponse>('/system/health');
}

