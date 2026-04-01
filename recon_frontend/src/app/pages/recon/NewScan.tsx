import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { Play, Settings, Target, Zap } from 'lucide-react';

import { getRecentScans } from '../../../api/dashboard';
import { createScan, validateTargets } from '../../../api/scans';
import { handleApiError } from '../../../utils/errorHandler';
import { useAuth } from '../../context/AuthContext';
import { toast } from 'sonner';

type ScanTypeUi = 'passive' | 'active' | 'full';

const ALL_SCANNERS = [
  'subdomain_enum',
  'dns_enum',
  'whois',
  'port_scan',
  'http_probe',
  'url_discovery',
  'ssl_check',
  'headers_analysis',
  'technology_fingerprint',
  'hosting_detection',
  'vulnerability_surface',
  'risk_scoring',
  'report_generation',
] as const;
type ScannerKey = (typeof ALL_SCANNERS)[number];

const scanConfig: Record<ScanTypeUi, readonly ScannerKey[]> = {
  passive: [
    'subdomain_enum',
    'dns_enum',
    'whois',
    'url_discovery',
    'headers_analysis',
    'technology_fingerprint',
    'hosting_detection',
  ],
  active: ['port_scan', 'http_probe', 'ssl_check', 'vulnerability_surface'],
  full: ALL_SCANNERS,
};

type ScanOptionKey =
  | 'portScanning'
  | 'dnsEnumeration'
  | 'subdomainDiscovery'
  | 'technologyDetection'
  | 'sslAnalysis'
  | 'screenshotCapture'
  | 'vulnerabilityAssessment';

const UI_OPTIONS: { key: ScanOptionKey; label: string; scanner: ScannerKey }[] = [
  { key: 'subdomainDiscovery', label: 'Subdomain Discovery', scanner: 'subdomain_enum' },
  { key: 'dnsEnumeration', label: 'DNS Enumeration', scanner: 'dns_enum' },
  { key: 'technologyDetection', label: 'Technology Detection', scanner: 'technology_fingerprint' },
  { key: 'portScanning', label: 'Port Scanning', scanner: 'port_scan' },
  { key: 'sslAnalysis', label: 'SSL Analysis', scanner: 'ssl_check' },
  { key: 'screenshotCapture', label: 'Screenshot Capture', scanner: 'http_probe' },
  { key: 'vulnerabilityAssessment', label: 'Vulnerability Assessment', scanner: 'vulnerability_surface' },
];

function uniqueScanners(scanners: readonly ScannerKey[]) {
  return Array.from(new Set(scanners));
}

function buildOptionsPayload(scanners: readonly ScannerKey[]) {
  const selected = new Set(scanners);
  return {
    portScanning: selected.has('port_scan'),
    sslAnalysis: selected.has('ssl_check'),
    dnsEnumeration: selected.has('dns_enum'),
    subdomainDiscovery: selected.has('subdomain_enum'),
    technologyDetection: selected.has('technology_fingerprint'),
    vulnerabilityAssessment: selected.has('vulnerability_surface'),
    screenshotCapture: selected.has('http_probe'),
  };
}

function parseTargets(raw: string) {
  return raw
    .split(/[\n,]+/g)
    .map((t) => t.trim())
    .filter(Boolean);
}

function getScanTypeLabel(type?: string, fallback?: string) {
  if (type === 'quick_scan') return 'Passive Scan';
  if (type === 'custom_scan') return 'Active Scan';
  if (type === 'full_scan') return 'Full Scan';
  return fallback || 'N/A';
}

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const [targetsText, setTargetsText] = useState(searchParams.get('target') ?? '');
  const [scanType, setScanType] = useState<ScanTypeUi>('passive');
  const [selectedScanners, setSelectedScanners] = useState<ScannerKey[]>(() => [...scanConfig.passive]);
  const [schedule, setSchedule] = useState<'immediate' | 'later'>('immediate');
  const [scheduledDate, setScheduledDate] = useState('');
  const [scheduledTime, setScheduledTime] = useState('');
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [validationSummary, setValidationSummary] = useState<{ valid: number; invalid: number } | null>(null);

  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    setSelectedScanners([...scanConfig[scanType]]);
  }, [scanType]);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await getRecentScans({ limit: 5, offset: 0 });
        if (mounted) setRecentScans(Array.isArray(data?.scans) ? data.scans : []);
      } catch {
        if (mounted) setRecentScans([]);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (isAdmin) {
      setScanType('full');
      return;
    }

    setScanType((prev) => (prev === 'full' ? 'passive' : prev));
  }, [isAdmin]);

  const scanTypes = useMemo(
    () => [
      { id: 'passive' as const, name: 'Passive Scan', icon: Target, description: 'Passive recon scanners only', duration: '~1-5 minutes' },
      { id: 'active' as const, name: 'Active Scan', icon: Zap, description: 'Interactive probing scanners', duration: '~5-20 minutes' },
      { id: 'full' as const, name: 'Full Scan', icon: Settings, description: 'All supported scanners', duration: '~15-60 minutes' },
    ],
    [],
  );

  const [notifications, setNotifications] = useState({
    emailOnCompletion: true,
    notifyOnCriticalFindings: true,
    slackWebhook: '',
    customWebhook: '',
  });

  const optionsPayload = useMemo(() => buildOptionsPayload(selectedScanners), [selectedScanners]);
  const scanTypeMap = useMemo(() => ({ passive: 'quick_scan', active: 'custom_scan', full: 'full_scan' } as const), []);

  const buildScheduledAt = () => {
    if (!scheduledDate || !scheduledTime) return null;
    const dt = new Date(`${scheduledDate}T${scheduledTime}`);
    return Number.isNaN(dt.getTime()) ? null : dt.toISOString();
  };

  const onValidate = async () => {
    const targets = parseTargets(targetsText);
    if (!targets.length) {
      setValidationSummary(null);
      return;
    }

    try {
      const result = await validateTargets(targets);
      setValidationSummary({ valid: result.summary.validTargets, invalid: result.summary.invalidTargets });
    } catch (error) {
      handleApiError(error);
      setValidationSummary(null);
    }
  };

  const onStart = async () => {
    const targets = parseTargets(targetsText);
    if (!targets.length) {
      toast.error('At least one target is required');
      return;
    }

    setSubmitting(true);
    try {
      const scheduledAt = schedule === 'later' ? buildScheduledAt() : null;
      if (schedule === 'later' && !scheduledAt) {
        toast.error('Scheduled date and time are required');
        return;
      }

      const response = await createScan({
        targets,
        scanType: scanTypeMap[scanType],
        options: optionsPayload,
        schedule: schedule === 'later' ? { type: 'scheduled', scheduledAt } : { type: 'immediate', scheduledAt: null },
        notifications: {
          emailOnCompletion: notifications.emailOnCompletion,
          notifyOnCriticalFindings: notifications.notifyOnCriticalFindings,
          slackWebhook: notifications.slackWebhook.trim() || null,
          customWebhook: notifications.customWebhook.trim() || null,
        },
        priority: 'normal',
        name: null,
        description: null,
        tags: [],
      });

      navigate(`/scan/${response.scanId}`);
    } catch (error) {
      handleApiError(error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">Configure New Scan</h1>
        <p className="text-gray-500 mt-1">Create a scan job via the backend scan API</p>
      </div>

      <div className="max-w-4xl mx-auto space-y-6">
        <div className="bg-white rounded-2xl p-6 shadow-sm">
          <h3 className="text-xl font-semibold text-gray-900 mb-6">Scan Configuration</h3>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-900 mb-2">Scan Targets</label>
            <textarea
              rows={4}
              value={targetsText}
              onChange={(event) => setTargetsText(event.target.value)}
              onBlur={() => void onValidate()}
              placeholder="Enter one target per line\nExample:\nacme-corp.com\n203.0.113.0/24\n*.acme-corp.com"
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
            />
            {validationSummary ? (
              <p className="text-sm text-gray-500 mt-2">
                Validation: {validationSummary.valid} valid, {validationSummary.invalid} invalid
              </p>
            ) : (
              <p className="text-sm text-gray-500 mt-2">Targets are validated automatically when you leave the field.</p>
            )}
          </div>

          <div className="mb-8">
            <label className="block text-sm font-medium text-gray-900 mb-4">Scan Type</label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {scanTypes.map((type) => {
                const Icon = type.icon;
                const disabled = type.id === 'full' && !isAdmin;
                return (
                  <button
                    key={type.id}
                    type="button"
                    onClick={() => setScanType(type.id)}
                    disabled={disabled}
                    className={`
                      p-4 rounded-xl border-2 text-left transition-all
                      ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
                      ${scanType === type.id ? 'border-blue-500 bg-blue-50 shadow-lg shadow-blue-500/20' : 'border-gray-200 bg-white hover:border-gray-300'}
                    `}
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${scanType === type.id ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-600'}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900">{type.name}</h4>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{type.description}</p>
                    <p className="text-xs text-gray-500">{type.duration}</p>
                  </button>
                );
              })}
            </div>
            {!isAdmin ? (
              <p className="text-xs text-gray-500 mt-2">Full Scan requires admin role.</p>
            ) : null}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-900 mb-4">Scan Options</label>
            <p className="text-xs text-gray-500 mb-3">Options are selected automatically based on scan type.</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {UI_OPTIONS.map((opt) => (
                <label key={opt.key} className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 cursor-not-allowed">
                  <input type="checkbox" checked={selectedScanners.includes(opt.scanner)} readOnly disabled className="w-5 h-5 text-blue-500 border-gray-300 rounded focus:ring-blue-500" />
                  <span className="text-gray-700">{opt.label}</span>
                </label>
              ))}
            </div>

            <div className="mt-6">
              <label className="block text-sm font-medium text-gray-900 mb-2">Scanners Included</label>
              <p className="text-xs text-gray-500 mb-3">
                {uniqueScanners(selectedScanners).length} / {ALL_SCANNERS.length} scanners enabled for this scan type.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {ALL_SCANNERS.map((scanner) => (
                  <label key={scanner} className="flex items-center gap-3 p-2 rounded-lg bg-gray-50">
                    <input type="checkbox" checked={selectedScanners.includes(scanner)} readOnly disabled className="w-4 h-4 text-blue-500 border-gray-300 rounded focus:ring-blue-500" />
                    <span className="text-xs text-gray-700 font-mono">{scanner}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-6 shadow-sm">
          <h3 className="text-xl font-semibold text-gray-900 mb-6">Schedule & Notifications</h3>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-900 mb-4">Scan Schedule</label>
            <div className="space-y-3">
              <label className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input type="radio" name="schedule" checked={schedule === 'immediate'} onChange={() => setSchedule('immediate')} className="w-5 h-5 text-blue-500 border-gray-300 focus:ring-blue-500" />
                <span className="text-gray-700">Run immediately</span>
              </label>
              <label className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input type="radio" name="schedule" checked={schedule === 'later'} onChange={() => setSchedule('later')} className="w-5 h-5 text-blue-500 border-gray-300 focus:ring-blue-500" />
                <span className="text-gray-700">Schedule for later</span>
              </label>
            </div>

            {schedule === 'later' ? (
              <div className="mt-4 p-4 bg-gray-50 rounded-xl grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Date</label>
                  <input type="date" value={scheduledDate} onChange={(e) => setScheduledDate(e.target.value)} className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Time</label>
                  <input type="time" value={scheduledTime} onChange={(e) => setScheduledTime(e.target.value)} className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
                </div>
              </div>
            ) : null}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <label className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 cursor-pointer">
              <input type="checkbox" checked={notifications.emailOnCompletion} onChange={() => setNotifications((p) => ({ ...p, emailOnCompletion: !p.emailOnCompletion }))} className="w-5 h-5 text-blue-500 border-gray-300 rounded focus:ring-blue-500" />
              <span className="text-gray-700">Email on completion</span>
            </label>
            <label className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 cursor-pointer">
              <input type="checkbox" checked={notifications.notifyOnCriticalFindings} onChange={() => setNotifications((p) => ({ ...p, notifyOnCriticalFindings: !p.notifyOnCriticalFindings }))} className="w-5 h-5 text-blue-500 border-gray-300 rounded focus:ring-blue-500" />
              <span className="text-gray-700">Notify on critical findings</span>
            </label>
          </div>

          <div className="flex items-center justify-between">
            <button type="button" onClick={() => void onStart()} disabled={submitting} className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-blue-500 to-blue-600 text-white font-medium hover:shadow-lg disabled:opacity-60">
              <Play className="w-5 h-5" />
              {submitting ? 'Starting...' : 'Start Scan'}
            </button>
            <button type="button" onClick={() => void onValidate()} className="text-sm text-gray-600 hover:text-gray-900">
              Validate targets
            </button>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-6 shadow-sm">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">Recent Scans</h3>
          <div className="space-y-2">
            {recentScans.map((scan, idx) => (
              <button
                key={scan?.id ?? idx}
                type="button"
                onClick={() => {
                  if (scan?.id) navigate(`/scan/${scan.id}`);
                }}
                className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-gray-50"
              >
                <div className="text-left">
                  <p className="text-sm font-medium text-gray-900">{scan?.target || 'N/A'}</p>
                  <p className="text-xs text-gray-500">
                    {getScanTypeLabel(scan?.type, scan?.typeLabel)} {' \u2022 '} {scan?.status || 'N/A'}
                  </p>
                </div>
                <span className="text-xs text-gray-500">{scan?.relativeTime || ''}</span>
              </button>
            ))}
            {!recentScans.length ? <p className="text-sm text-gray-500">No recent scans.</p> : null}
          </div>
        </div>
      </div>
    </div>
  );
}
