// Types for the SOC console API (design core-v1 §6). Indicator values are display-only.

export type IncidentStatus = 'open' | 'investigating' | 'resolved';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingDomain = 'phishing' | 'malware' | 'network' | 'host';
export type Resolution = 'true_positive' | 'false_positive' | 'benign' | 'duplicate';
export type IndicatorType = 'domain' | 'url' | 'ip' | 'hash' | 'phone' | 'email';
export type AttackMatrix = 'enterprise' | 'mobile';

export interface IncidentSummary {
  id: number;
  title: string;
  domain: FindingDomain;
  severity: Severity;
  status: IncidentStatus;
  resolution: Resolution | null;
  campaign_id: number | null;
  reopened_from: number | null;
  opened_at: string;
  last_activity_at: string;
  resolved_at: string | null;
  finding_count: number;
  brands: string[];
}

export interface IncidentsQueryParams {
  status?: IncidentStatus;
  severity?: Severity;
  domain?: FindingDomain;
  brand?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export interface IncidentsResponse {
  total_matching: number;
  limit: number;
  offset: number;
  results: IncidentSummary[];
}

export interface IncidentFinding {
  id: string;
  kind: string;
  severity: Severity;
  confidence: 'confirmed' | 'corroborated' | 'single_signal' | 'undetermined';
  engine_name: string;
  engine_version: string;
  observed_at: string;
  source_kind: string;
  reasons: string[];
  verdict: string | null;
  attack: { technique_id: string; matrix: AttackMatrix }[];
}

export interface IncidentIndicator {
  id: number;
  type: IndicatorType;
  value_hash: string;
  value: string | null;
  registered_domain: string | null;
  hash_algo: string | null;
  sources: string[];
  roles: string[];
}

export interface IncidentTechnique {
  technique_id: string;
  matrix: AttackMatrix;
  attack_version: string;
  name: string | null;
  count: number;
}

export interface IncidentEvent {
  id: number;
  actor: string;
  action: string;
  from_status: IncidentStatus | null;
  to_status: IncidentStatus | null;
  note: string | null;
  at: string;
}

export interface IncidentDetail extends IncidentSummary {
  campaign: { id: number; name: string } | null;
  expired_findings: number;
  findings: IncidentFinding[];
  indicators: IncidentIndicator[];
  techniques: IncidentTechnique[];
  events: IncidentEvent[];
  links: { incident_id: number; related_incident_id: number; relation: 'related' | 'merged_into' }[];
}

export interface IncidentUpdate {
  status?: IncidentStatus;
  resolution?: Resolution;
  note?: string;
}

export interface Campaign {
  id: number;
  name: string;
  description: string | null;
  status: string;
  created_at: string;
  incident_count: number;
}

export interface CampaignSuggestion {
  incident_ids: number[];
  reason: 'shared_contact' | 'shared_brand_and_indicator';
  brands: string[];
  shared_indicator_types: IndicatorType[];
}
