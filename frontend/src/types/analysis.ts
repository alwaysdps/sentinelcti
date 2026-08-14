/**
 * Types mirroring the backend's Pydantic response models.
 *
 * These are hand-maintained rather than generated from the OpenAPI schema:
 * for an API this size the generator toolchain costs more than it saves, and
 * `npm run build` fails loudly the moment a component reads a field the
 * backend no longer sends.
 */

export type IndicatorType = 'url' | 'domain' | 'ip' | 'hash' | 'file';

export type Verdict = 'clean' | 'low_risk' | 'suspicious' | 'high_risk' | 'critical';

export type AnalysisStatus = 'completed' | 'partial' | 'failed';

export type Severity = 'pass' | 'info' | 'low' | 'medium' | 'high';

export type ProviderVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error';

export interface Finding {
  code: string;
  title: string;
  description: string;
  points: number;
  severity: Severity;
  category: string;
  mitre: string[];
}

export interface ProviderResult {
  provider: string;
  result: ProviderVerdict;
  detail: string;
  score_contribution: number;
  reference_url: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  url: string;
  confidence: string;
}

export interface ScoreBreakdownItem {
  code: string;
  title: string;
  points: number;
  severity: Severity;
  category: string;
}

export interface Scoring {
  score: number;
  verdict: Verdict;
  summary: string;
  base_points: number;
  corroboration_bonus: number;
  floor_applied: number;
  floor_reason: string | null;
  capped_at_maximum: boolean;
  breakdown: ScoreBreakdownItem[];
}

export interface AnalysisSummary {
  id: number;
  reference: string;
  indicator_type: IndicatorType;
  indicator_display: string;
  risk_score: number;
  verdict: Verdict;
  status: AnalysisStatus;
  created_at: string;
  duration_seconds: number;
  is_demo: boolean;
}

/** Free-form technical detail; its shape varies by indicator type. */
export type AnalysisDetails = Record<string, unknown> & { scoring?: Scoring };

export interface Analysis extends AnalysisSummary {
  indicator: string;
  findings: Finding[];
  details: AnalysisDetails;
  provider_results: ProviderResult[];
  mitre_techniques: MitreTechnique[];
}

export interface PaginatedAnalyses {
  items: Analysis[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ActivityPoint {
  date: string;
  count: number;
  malicious: number;
}

export interface DashboardStats {
  total_analyses: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  average_risk_score: number;
  by_verdict: Record<Verdict, number>;
  by_indicator_type: Record<IndicatorType, number>;
  activity: ActivityPoint[];
  recent: AnalysisSummary[];
}

export interface RiskBand {
  min: number;
  max: number;
  verdict: Verdict;
  summary: string;
}

export interface ProviderStatus {
  name: string;
  display_name: string;
  enabled: boolean;
  configured: boolean;
  requires_network: boolean;
}

export interface EdgeStatus {
  client_ip_source: string;
  trusted_proxy_count: number;
  behind_cloudflare: boolean;
  forwarding_headers_trusted: boolean;
  warning: string | null;
}

export interface PlatformConfig {
  app_name: string;
  version: string;
  environment: string;
  max_upload_bytes: number;
  delete_uploads_after_analysis: boolean;
  dns_lookups_enabled: boolean;
  active_url_fetch_enabled: boolean;
  rate_limit_requests: number;
  rate_limit_window_seconds: number;
  risk_bands: RiskBand[];
  providers: ProviderStatus[];
  edge: EdgeStatus;
}

export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  database: string;
  providers: ProviderStatus[];
  analyses_stored: number;
}

export interface HistoryQuery {
  page?: number;
  page_size?: number;
  search?: string;
  indicator_type?: IndicatorType | '';
  verdict?: Verdict | '';
  min_score?: number;
  max_score?: number;
  sort_by?: string;
  sort_dir?: 'asc' | 'desc';
}
