import type { Severity } from '../api/socTypes';
import type { ScanStatus } from './ScanSurface';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const TONE: Record<Severity, ScanStatus> = {
  critical: 'HIGH', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'loaded',
};

// File scans and network imports report individual findings, not a phishing verdict.
export function detailStatus(detail: { findings: { severity: Severity }[] } | null): { severity?: Severity; status: ScanStatus } {
  const severity = SEVERITIES.find(level => detail?.findings.some(finding => finding.severity === level));
  return { severity, status: severity ? TONE[severity] : detail ? 'loaded' : 'scanning' };
}
