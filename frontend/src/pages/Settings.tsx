/**
 * Platform configuration, read-only.
 *
 * Everything here comes from `/api/config`, which reports capability state and
 * never credentials: the page can tell you a provider is configured, never
 * what configures it.
 */

import {
  Card,
  DefinitionRow,
  ErrorState,
  InlineNotice,
  LoadingState,
  PageHeader,
  VerdictBadge,
} from '../components/ui';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';
import { formatBytes } from '../lib/format';
import type { Verdict } from '../types/analysis';

function Toggle({ on, onLabel, offLabel }: { on: boolean; onLabel: string; offLabel: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-sm ${on ? 'text-verdict-clean' : 'text-content-muted'}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-verdict-clean' : 'bg-content-muted'}`}
        aria-hidden
      />
      {on ? onLabel : offLabel}
    </span>
  );
}

export default function Settings() {
  const { data, loading, error, refresh } = useFetch(() => api.config(), []);

  if (loading) return <LoadingState label="Loading configuration…" />;
  if (error || !data) {
    return (
      <ErrorState message={error?.message ?? 'Configuration unavailable.'} onRetry={refresh} />
    );
  }

  return (
    <>
      <PageHeader
        title="Settings"
        subtitle="How this instance is configured. Values are set through environment variables and are read-only here."
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Instance">
          <dl>
            <DefinitionRow label="Application">{data.app_name}</DefinitionRow>
            <DefinitionRow label="Version">{data.version}</DefinitionRow>
            <DefinitionRow label="Environment">{data.environment}</DefinitionRow>
            <DefinitionRow label="Rate limit">
              {data.rate_limit_requests} requests / {data.rate_limit_window_seconds}s per client
            </DefinitionRow>
          </dl>
        </Card>

        <Card
          title="Analysis safety"
          description="Controls governing what the platform is permitted to do."
        >
          <dl>
            <DefinitionRow label="Maximum upload size">
              {formatBytes(data.max_upload_bytes)}
            </DefinitionRow>
            <DefinitionRow label="Delete uploads after analysis">
              <Toggle
                on={data.delete_uploads_after_analysis}
                onLabel="Enabled — bytes discarded, hashes retained"
                offLabel="Disabled — samples retained in quarantine"
              />
            </DefinitionRow>
            <DefinitionRow label="Passive DNS lookups">
              <Toggle
                on={data.dns_lookups_enabled}
                onLabel="Enabled — resolver queried, indicator not contacted"
                offLabel="Disabled — analysis is fully offline"
              />
            </DefinitionRow>
            <DefinitionRow label="Active URL fetching">
              <Toggle
                on={data.active_url_fetch_enabled}
                onLabel="Enabled"
                offLabel="Disabled — submitted URLs are never requested"
              />
            </DefinitionRow>
          </dl>
          <div className="mt-4">
            <InlineNotice>
              File execution is not a configurable option. Uploaded samples are never run,
              extracted, or parsed by a format handler under any configuration.
            </InlineNotice>
          </div>
        </Card>

        <Card
          title="Threat intelligence providers"
          description="Add a provider by implementing the ThreatIntelProvider interface and listing it in ENABLED_PROVIDERS."
        >
          <ul className="space-y-3">
            {data.providers.map((provider) => (
              <li
                key={provider.name}
                className="flex items-start justify-between gap-4 border-b border-border-subtle pb-3 last:border-0 last:pb-0"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-content-primary">
                    {provider.display_name}
                  </p>
                  <p className="mt-0.5 text-xs text-content-muted">
                    {provider.requires_network
                      ? 'External service — requires network access and an API key.'
                      : 'Offline heuristic engine — no network access required.'}
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <Toggle on={provider.enabled} onLabel="Enabled" offLabel="Disabled" />
                  {provider.enabled && !provider.configured && (
                    <p className="mt-0.5 text-xs text-verdict-suspicious">Not configured</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>

        <Card
          title="Edge & client identification"
          description="How this instance determines who a request came from. Rate limiting is only meaningful if this is correct."
        >
          <dl>
            <DefinitionRow label="Client address read from">
              <span className="mono">{data.edge.client_ip_source}</span>
            </DefinitionRow>
            <DefinitionRow label="Forwarding headers">
              <Toggle
                on={data.edge.forwarding_headers_trusted}
                onLabel="Trusted from listed proxies only"
                offLabel="Ignored — socket peer always used"
              />
            </DefinitionRow>
            <DefinitionRow label="Behind Cloudflare">
              <Toggle
                on={data.edge.behind_cloudflare}
                onLabel="Yes — edge ranges trusted"
                offLabel="No"
              />
            </DefinitionRow>
            <DefinitionRow label="Trusted proxy ranges">
              {data.edge.trusted_proxy_count}
            </DefinitionRow>
          </dl>

          <div className="mt-4">
            {data.edge.warning ? (
              // Surfaced because this misconfiguration has no runtime symptom:
              // rate limiting still runs, it just stops distinguishing clients.
              <InlineNotice tone="warning">
                <strong className="text-content-primary">Configuration mismatch.</strong>{' '}
                {data.edge.warning}
              </InlineNotice>
            ) : (
              <InlineNotice>
                Forwarding headers are honoured only when the socket peer — which cannot be forged
                over TCP — is a listed proxy. With none configured, headers are ignored entirely, so
                the default configuration is the safe one.
              </InlineNotice>
            )}
          </div>
        </Card>

        <Card
          title="Risk score bands"
          description="How a numeric score maps to a verdict. Applied identically to every indicator type."
        >
          <ul className="space-y-2.5">
            {data.risk_bands.map((band) => (
              <li key={band.verdict} className="flex items-start gap-3">
                <span className="mt-0.5 w-16 shrink-0 text-right font-mono text-xs text-content-muted tabular-nums">
                  {band.min}–{band.max}
                </span>
                <div className="min-w-0">
                  <VerdictBadge verdict={band.verdict as Verdict} />
                  <p className="mt-1 text-xs text-content-secondary">{band.summary}</p>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="mt-5">
        <Card title="Authentication">
          <p className="text-sm leading-relaxed text-content-secondary">
            This MVP runs without authentication so the threat-analysis engine stays the focus. The
            backend is structured to accept it without rework: every route is mounted through a
            single <code className="mono text-content-primary">api_router</code>, so a global{' '}
            <code className="mono text-content-primary">Depends(require_user)</code> would apply
            across the API in one line. Deploy this instance on a trusted network only.
          </p>
        </Card>
      </div>
    </>
  );
}
