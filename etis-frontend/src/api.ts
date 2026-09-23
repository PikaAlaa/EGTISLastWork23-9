const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const API_KEY = import.meta.env.VITE_ETIS_API_KEY || ''

export type EngineResult = {
  applicable: boolean
  score: number | null
  reason: string
  [key: string]: unknown
}

export type AnalyzeResponse = {
  final_score: number
  verdict: 'LOW' | 'MEDIUM' | 'HIGH'
  reason: string
  engines_applied: string[]
  weighted_contributions: Record<string, number>
  engine_details: Record<string, EngineResult>
  saved: boolean
  save_error: string | null
}

export type Threat = {
  id: number
  url: string
  domain: string
  source: string
  brand_target: string | null
  first_seen: string
  last_seen: string
}

export type Stats = {
  blacklist_total: number
  blacklist_by_source: Record<string, number>
  scans_total: number
  verdict_counts: Record<string, number>
  model_available: boolean
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers)
  headers.set('Content-Type', 'application/json')
  if (API_KEY) headers.set('X-API-Key', API_KEY)
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail?.[0]?.msg || body?.detail || body?.error?.message || `Request failed (${response.status})`)
  }
  return response.json()
}

export const api = {
  analyze: (payload: { text?: string; url?: string }) => request<AnalyzeResponse>('/analyze', { method: 'POST', body: JSON.stringify(payload) }),
  threats: (page = 1, filters: { source?: string; domain?: string } = {}) => {
    const params = new URLSearchParams({ page: String(page), page_size: '20' })
    if (filters.source) params.set('source', filters.source)
    if (filters.domain) params.set('domain', filters.domain)
    return request<{ items: Threat[]; total: number; page: number; page_size: number }>(`/threats?${params}`)
  },
  stats: () => request<Stats>('/stats'),
}
