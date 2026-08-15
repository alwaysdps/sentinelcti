/**
 * Typed API client.
 *
 * One rule drives the error handling here: the user never sees a raw backend
 * message they cannot act on. The backend returns a structured envelope
 * (`{ error: { code, message } }`); this layer turns that into an `ApiError`
 * carrying a code the UI can branch on and a message written for a human.
 * Anything unrecognised (a proxy 502, a dropped connection) is translated into
 * a plain-language equivalent rather than surfaced verbatim.
 */

import type {
  Analysis,
  DashboardStats,
  HealthResponse,
  HistoryQuery,
  PaginatedAnalyses,
  PlatformConfig,
} from '../types/analysis';

/**
 * API base URL.
 *
 * Defaults to a relative path, which keeps the browser on one origin — true in
 * dev (Vite proxy), in Docker (nginx), and on Vercel if you configure a rewrite.
 * Same-origin means no CORS grant is needed at all, which is one fewer thing to
 * get wrong.
 *
 * `VITE_API_BASE_URL` overrides it for deployments where the API lives on a
 * different host (frontend on Vercel, backend on Render/Railway/Fly). Set it in
 * the Vercel dashboard as e.g. `https://sentinelcti-api.onrender.com/api`, and
 * add the Vercel origin to the backend's `CORS_ORIGINS`.
 *
 * Read at build time, so it is baked into the bundle — it is a public URL, not
 * a secret, and Vite only exposes `VITE_`-prefixed variables for exactly this
 * reason.
 */
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '/api').replace(/\/+$/, '');

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(message: string, code: string, status: number, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }

  /** Whether retrying the same request unchanged could plausibly succeed. */
  get isRetryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string; details?: Record<string, unknown> };
}

async function toApiError(response: Response): Promise<ApiError> {
  let body: ErrorEnvelope = {};
  try {
    body = (await response.json()) as ErrorEnvelope;
  } catch {
    // Non-JSON error bodies (a proxy error page, an empty 502) are expected;
    // fall through to the status-based fallback below.
  }

  const code = body.error?.code ?? 'http_error';
  const message = body.error?.message ?? fallbackMessage(response.status);
  return new ApiError(message, code, response.status, body.error?.details);
}

function fallbackMessage(status: number): string {
  if (status === 401) return 'This instance requires an access token.';
  if (status === 404) return 'That analysis could not be found.';
  if (status === 413) return 'That file is larger than the upload limit.';
  if (status === 429) return 'Too many requests. Wait a moment and try again.';
  if (status >= 500) return 'The analysis service is unavailable. Please try again shortly.';
  return 'The request could not be completed.';
}

/**
 * Optional shared-token gate (see backend `core/access.py`).
 *
 * Stored in sessionStorage rather than localStorage so it dies with the tab —
 * a demo token left behind on a shared machine is exactly the kind of thing
 * that outlives its usefulness. Sent as a header, never a query parameter,
 * which would leak it into server logs and browser history.
 */
const TOKEN_KEY = 'sentinelcti.access_token';

/**
 * Anonymous workspace key.
 *
 * Generated once per browser and sent with every request, so each visitor sees
 * only their own analyses (plus the shared demo data) without ever creating an
 * account. See the backend's `core/owner.py` for the threat model.
 *
 * localStorage, not sessionStorage: history should survive closing the tab,
 * which is the whole point. It does not survive clearing site data — an
 * accepted trade for having no login.
 *
 * 256 bits from the platform CSPRNG. Guessing another workspace has to be
 * infeasible, because holding the key *is* the claim to it.
 */
const WORKSPACE_KEY = 'sentinelcti.workspace';

function createWorkspaceKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function getWorkspaceKey(): string {
  try {
    let key = localStorage.getItem(WORKSPACE_KEY);
    if (!key || !/^[A-Za-z0-9_-]{32,64}$/.test(key)) {
      key = createWorkspaceKey();
      localStorage.setItem(WORKSPACE_KEY, key);
    }
    return key;
  } catch {
    // Storage blocked (private mode, hardened settings). The app still works;
    // the server treats a missing key as "no workspace", so the visitor sees
    // the shared demo data and their submissions simply are not retained.
    return '';
  }
}

/** Discards this browser's history by starting a fresh workspace. */
export function resetWorkspace(): void {
  try {
    localStorage.setItem(WORKSPACE_KEY, createWorkspaceKey());
  } catch {
    /* storage unavailable — nothing was being retained anyway */
  }
}

export function setAccessToken(token: string): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export function getAccessToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? '';
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const token = getAccessToken();
  if (token) headers['X-Access-Token'] = token;

  // Sent as a header, never a query parameter: a key in the URL would leak
  // into server logs, browser history and the Referer sent to third parties.
  const workspace = getWorkspaceKey();
  if (workspace) headers['X-Owner-Key'] = workspace;

  return headers;
}

/**
 * Global 401 hook.
 *
 * Registered once by the router. Without it every page renders a dead-end
 * "something went wrong" with a retry button that can never succeed, because
 * the missing token is not something retrying fixes — the user has to be sent
 * somewhere they can supply it.
 */
type UnauthorizedHandler = (method: string) => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
        ...authHeaders(),
        ...init?.headers,
      },
    });
  } catch {
    // status 0 distinguishes "never reached the server" from any HTTP status.
    throw new ApiError(
      'Cannot reach the SentinelCTI backend. Check that it is running.',
      'network_error',
      0,
    );
  }

  if (!response.ok) {
    const error = await toApiError(response);
    if (error.status === 401) {
      // Drop the stored token: it is either absent or not accepted, and
      // keeping it would make the login form fail silently on first try.
      setAccessToken('');
      unauthorizedHandler?.((init?.method ?? 'GET').toUpperCase());
    }
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function toQueryString(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

export const api = {
  health: () => request<HealthResponse>('/health'),

  config: () => request<PlatformConfig>('/config'),

  dashboard: (activityDays = 30) =>
    request<DashboardStats>(`/stats/dashboard?activity_days=${activityDays}`),

  analyzeUrl: (url: string) =>
    request<Analysis>('/analyze/url', { method: 'POST', body: JSON.stringify({ url }) }),

  analyzeDomain: (domain: string) =>
    request<Analysis>('/analyze/domain', { method: 'POST', body: JSON.stringify({ domain }) }),

  analyzeIp: (ip: string) =>
    request<Analysis>('/analyze/ip', { method: 'POST', body: JSON.stringify({ ip }) }),

  analyzeHash: (hash: string) =>
    request<Analysis>('/analyze/hash', { method: 'POST', body: JSON.stringify({ hash }) }),

  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<Analysis>('/analyze/file', { method: 'POST', body: form });
  },

  listAnalyses: (query: HistoryQuery = {}) =>
    request<PaginatedAnalyses>(`/analyses${toQueryString(query as Record<string, unknown>)}`),

  getAnalysis: (identifier: string) => request<Analysis>(`/analyses/${identifier}`),

  deleteAnalysis: (identifier: string) =>
    request<{ deleted: boolean; reference: string }>(`/analyses/${identifier}`, {
      method: 'DELETE',
    }),
};
