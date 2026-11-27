// Types for the network.windows import API (design network-windows-v1 §6.7, §6.8, §7). Read-only.
// No field carries a domain, address, port per event, process, user or computer name, or path:
// devices appear only as keyed device_ref values.
import type { AttackMatrix, Severity } from './socTypes';

export type NetworkKind =
  | 'known_bad_destination'
  | 'phishing_domain_lookup'
  | 'suspicious_domain'
  | 'beaconing'
  | 'unusual_port'
  | 'dns_tunnelling_signs'
  | 'rare_destination';
export type NetworkHealthReason =
  | 'rules_missing'
  | 'blocklists_missing'
  | 'blocklists_stale'
  | 'indicator_store_empty'
  | 'url_model_unavailable'
  | 'blocklist_source_stale';
export type DetectionState = 'visible' | 'partial' | 'not_visible' | 'no_baseline' | 'inactive';
export type SourceName = 'dns_client' | 'sysmon22' | 'firewall' | 'sysmon3' | 'snapshot';

export interface InputFileSummary {
  source: string;
  sha256: string;
  size: number;
  records: number;
}

export interface Coverage {
  detections?: Record<string, DetectionState>;
  not_visible?: string[];
  not_run?: Record<string, string>;
  baseline?: '24h' | 'none';
  import_hours?: number;
  firewall_time_basis?: string | null;
  sources?: Partial<Record<SourceName, { records: number; hours?: number | null }>>;
}

export interface NetworkImportSummary {
  id: number;
  started_at: string;
  finished_at: string | null;
  engine_version: string;
  manifest_sha256: string | null;
  lists_lock_sha256: string | null;
  span_first: string | null;
  span_last: string | null;
  files: InputFileSummary[];
  counts: { events: Record<string, number>; skipped: Record<string, number>; alerts: number };
  coverage: Coverage;
  findings_by_kind: Partial<Record<NetworkKind, number>>;
}

export interface NetworkImportsResponse {
  total_matching: number;
  limit: number;
  offset: number;
  results: NetworkImportSummary[];
}

export interface ListAttribution {
  list: string;
  title: string;
  version: string;
  licence: string;
  link: string;
}

export interface NetworkAttackRef {
  technique_id: string;
  matrix: AttackMatrix;
  attack_version: string;
  basis: string;
  name: string | null;
}

export interface NetworkFinding {
  id: string;
  kind: NetworkKind;
  severity: Severity;
  confidence: 'confirmed' | 'corroborated' | 'single_signal' | 'undetermined';
  observed_at: string;
  incident_id: number | null;
  engine_version: string;
  reasons: string[];
  detection?: string;
  reason_codes?: string[];
  events?: number;
  combined_with?: string[];
  device_ref?: string | null;
  rule_validation?: 'samples' | 'unvalidated_on_samples';
  baseline?: '24h' | 'none';
  process_category?: 'known_process_hash' | 'unknown';
  attack_basis?: string[];
  window: { first: string | null; last: string | null };
  values: Record<string, number | string | null>;
  lists: ListAttribution[];
  attack: NetworkAttackRef[];
}

export interface NetworkImportDetail extends NetworkImportSummary {
  findings: NetworkFinding[];
}

export interface NetworkHealth {
  engine: 'network.windows';
  domain: 'network';
  source: 'registered_engine' | 'local_files';
  available: boolean;
  status: NetworkHealthReason | 'available';
  reason: NetworkHealthReason | null;
  reasons: NetworkHealthReason[];
  rules_detail: string | null;
  shipped_rules: string[];
  shipped_lists: string[];
  blocklist_ages?: { fetch_age_days: number | null; source_age_days: number | null } | null;
  version: string;
  imports_start_from: string;
  last_import: { id: number; started_at: string; engine_version: string } | null;
}
