import { apiRequest } from './client';

export type CreateScanRequest = {
  targets: string[];
  scanType: 'full_scan' | 'quick_scan' | 'custom_scan';
  options: {
    portScanning: boolean;
    sslAnalysis: boolean;
    dnsEnumeration: boolean;
    subdomainDiscovery: boolean;
    technologyDetection: boolean;
    vulnerabilityAssessment: boolean;
    screenshotCapture: boolean;
  };
  schedule: { type: 'immediate' | 'scheduled'; scheduledAt: string | null };
  notifications: {
    emailOnCompletion: boolean;
    notifyOnCriticalFindings: boolean;
    slackWebhook: string | null;
    customWebhook: string | null;
  };
  priority: 'low' | 'normal' | 'high';
  name?: string | null;
  description?: string | null;
  tags?: string[];
};

export type CreateScanResponse = {
  scanId: string;
  status: string;
  estimatedStartTime: string | null;
  estimatedDuration: number;
  queuePosition: number;
  targetCount: number;
  message: string;
};

export type ValidateTargetsResponse = {
  valid: any[];
  invalid: any[];
  summary: { totalTargets: number; validTargets: number; invalidTargets: number };
};

export type ScanOptionsResponse = {
  options: { key: string; label: string; description: string; estimatedTime: number; requiresElevatedPermissions: boolean; defaultEnabled: boolean; category: string }[];
  categories: { id: string; label: string; description: string }[];
};

export type ScanDetailsResponse = {
  id: string;
  target: string;
  targets: string[];
  scanType: string;
  status: string;
  progress: number;
  startedAt: string | null;
  completedAt: string | null;
  duration: number | null;
  findings: { total: number; critical: number; high: number; medium: number; low: number };
  logs: { timestamp: string; level: string; message: string }[];
  results: { summary: string; detailedReport: string };
};

export function createScan(body: CreateScanRequest) {
  return apiRequest<CreateScanResponse>('/scans', { method: 'POST', body });
}

export function validateTargets(targets: string[]) {
  return apiRequest<ValidateTargetsResponse>('/scans/validate-targets', { method: 'POST', body: { targets } });
}

export function getScanOptions() {
  return apiRequest<ScanOptionsResponse>('/scans/options');
}

export function getScanById(scanId: string) {
  return apiRequest<ScanDetailsResponse>(`/scans/${encodeURIComponent(scanId)}`);
}

