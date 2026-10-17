export type SenderType = 'company_name' | 'short_code' | 'mobile_number' | 'unknown';
export interface AnalyzeRequest { url?: string; text?: string; sender_type?: SenderType }
export type Verdict = 'LOW' | 'MEDIUM' | 'HIGH' | 'INCOMPLETE';
export interface CheckedLink {
  url: string; host: string; bare: boolean; analysis_complete: boolean;
  brand: {score: number; matched_brand: string | null; technique: string | null; decisive: boolean;
    official_contact: {phone:string;source:string;verified_on:string;country:string}|null};
  patterns: [string, number, string | null][];
  blacklist: {score: number; match_type: 'exact' | 'domain' | null};
}
export interface AnalyzeResponse {
  verdict: Verdict; final_score: number; decisive_reason: string; supporting_signals: string[];
  checked_links: CheckedLink[]; links_truncated: boolean;
  text_finding: {score: number; probability: number; model: string; version: string; windows: number} | null;
  analysis_complete: boolean; checks_unavailable: string[]; policy_version: string;
  timing_ms: number; saved: boolean; save_error: string | null;
}
// ---- GET /threats ----

export interface ThreatEntry {
  id: number;
  domain: string;
  source: string;
  brand_target: string | null;
  reputation_score: number;
  is_active: boolean;
  first_seen: string; // ISO date, e.g. "2026-07-11"
  last_seen: string;
}

export interface ThreatsQueryParams {
  source?: string;
  is_active?: boolean;
  limit?: number; // backend default 50, max 500
  offset?: number; // backend default 0
}

export interface ThreatsResponse {
  total_matching: number;
  limit: number;
  offset: number;
  results: ThreatEntry[];
}

// ---- GET /stats ----
// Confirmed against a real response — matches _blacklist_stats()/
// _scan_stats() exactly. Index signatures kept since stats.py's own
// docstring says this is deliberately meant to grow over time.

export interface BlacklistStats {
  total_entries: number;
  active_entries: number;
  by_source: Record<string, number>;
  [key: string]: unknown;
}

export interface ScanStats {
  total_scans: number;
  by_verdict: Record<Verdict, number>;
  average_final_score: number | null;
  [key: string]: unknown;
}

export interface StatsResponse {
  blacklist: BlacklistStats;
  scans: ScanStats;
  [key: string]: unknown;
}
