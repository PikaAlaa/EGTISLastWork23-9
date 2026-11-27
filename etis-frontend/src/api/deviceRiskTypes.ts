// Types for the device-risk API, device-risk-v1 (design core-v2 §3.3-§3.5). Read-only.
// Devices are identified only by their stored srv:<32 hex> pseudonym.
import type { RecommendedAction, Severity } from './socTypes';

export type RiskBand = 'none' | 'low' | 'elevated' | 'high';

export interface DeviceRiskSummary {
  device_ref: string;
  band: RiskBand;
  points: number;
  counted_findings: number;
  engines: string[];
  last_finding_at: string | null;
  /** Null until the agent's 010_agent_devices exists: the device is "not paired". */
  device_status: string | null;
}

export interface DeviceRiskList {
  version: string;
  computed_at: string;
  total: number;
  results: DeviceRiskSummary[];
}

interface RiskRowBase {
  finding_id: string;
  engine_name: string;
  domain: string;
  kind: string;
  severity: Severity;
  confidence: string;
  observed_at: string;
  age_days: number;
  incident_id: number | null;
}

export interface CountedRow extends RiskRowBase {
  points_before_recency: number;
  points: number;
  recency: 'full' | 'half';
  repeats_not_counted: number;
  recommended_action: RecommendedAction | null;
  from_revoked_device: boolean | null;
}

export interface NotCountedRow extends RiskRowBase {
  reason: 'outside_window' | 'repeat' | `incident_resolved_${string}`;
  window_days?: number;
  points?: number;
}

export interface DeviceRiskDetail {
  device_ref: string;
  computed_at: string;
  device_status: string | null;
  version: string;
  points: number;
  band: RiskBand;
  counted: CountedRow[];
  cross_engine: { points: number; domains: string[] };
  not_counted: NotCountedRow[];
  windows: Record<string, { days: number; setting: string | null }>;
  window_days: number;
}
