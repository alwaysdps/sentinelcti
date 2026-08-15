/**
 * Platform configuration, read-only.
 *
 * Everything here comes from `/api/config`, which reports capability state and
 * never credentials: the page can tell you a provider is configured, never
 * what configures it.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
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
import { api, clearWorkspace } from '../services/api';
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

/**
 * Workspace control.
 *
 * The privacy policy tells people this exists, which is the reason it is here
 * rather than buried in the API client: a documented way to erase a history has
 * to be reachable without opening the developer console.
 *
 * It says "erase" because it now erases — the rows are deleted server-side
 * before the key is rotated. An earlier version could only hide them, and said
 * so; claiming erasure without performing it would have been the one wording
 * here that actually mattered.
 */
function WorkspaceCard() {
  const [confirming, setConfirming] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [failed, setFailed] = useState(false);

  async function handleClear() {
    setClearing(true);
    setFailed(false);
    try {
      await clearWorkspace();
    } catch {
      // The rows may still be there. Say so rather than navigating away and
      // letting a fresh empty history imply a deletion that did not happen.
      setFailed(true);
      setClearing(false);
      return;
    }
    // A hard navigation, not a router push: the dashboard and history views
    // hold data fetched under the previous key.
    window.location.assign('/dashboard');
  }

  return (
    <Card
      title="Your data"
      description="What this session has stored, and how to get rid of it now."
    >
      <p className="text-sm leading-relaxed text-content-secondary">
        There are no accounts here. Your browser generates a random key for this visit and sends it
        with each request, which is how the console shows you your own submissions and nobody
        else's. It identifies a browsing session, not a person.
      </p>

      <div className="mt-4">
        <InlineNotice>
          Your history is <strong className="text-content-primary">deleted when you leave</strong>.
          The key lives in session storage, so it goes when the tab closes, and the browser asks the
          server to delete the analyses it pointed at. Anything that outlives that request — a
          crashed tab, a dropped connection — is removed by the server's own retention sweep.
          Reopening the site later starts you empty.
        </InlineNotice>
      </div>

      <div className="mt-5 flex flex-wrap items-center gap-3">
        {confirming ? (
          <>
            <span className="text-sm text-content-secondary">
              Delete every analysis in this session?
            </span>
            <button
              type="button"
              onClick={handleClear}
              disabled={clearing}
              className="btn border border-verdict-critical/40 bg-verdict-critical/10 px-3 py-1.5 text-xs text-verdict-critical hover:bg-verdict-critical/20"
            >
              {clearing ? 'Deleting…' : 'Yes, delete it all'}
            </button>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              disabled={clearing}
              className="btn-ghost px-3 py-1.5 text-xs"
            >
              Cancel
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            className="btn-secondary px-4 py-2 text-xs"
          >
            Clear my history now
          </button>
        )}
      </div>

      {failed && (
        <p role="alert" className="mt-3 text-sm text-verdict-critical">
          Could not reach the server, so nothing was deleted. Try again.
        </p>
      )}

      <p className="mt-4 text-xs text-content-muted">
        What is stored, for how long, and how to remove it is set out in the{' '}
        <Link to="/privacy" className="text-accent hover:underline">
          privacy policy
        </Link>
        .
      </p>
    </Card>
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

        <WorkspaceCard />
      </div>
    </>
  );
}
