/**
 * Full threat analysis report.
 *
 * Structured so the two questions an analyst actually has are answered in
 * order: what is the verdict, and why. "Why was this flagged?" lists the
 * scored findings ahead of everything else, and the score breakdown shows the
 * arithmetic rather than asking the reader to trust the number.
 */

import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { RiskGauge } from '../components/RiskGauge';
import {
  Card,
  DefinitionRow,
  DemoBadge,
  ErrorState,
  IndicatorTypeBadge,
  InlineNotice,
  LoadingState,
  SeverityIcon,
  StatusBadge,
  VerdictBadge,
} from '../components/ui';
import { useFetch } from '../hooks/useAsync';
import { ApiError, api } from '../services/api';
import {
  SEVERITY_ORDER,
  formatDateTime,
  formatDetailValue,
  formatDuration,
  humanizeKey,
} from '../lib/format';
import type { Analysis, Finding, ProviderResult, Scoring } from '../types/analysis';

/* -------------------------------------------------------------------------- */

const PROVIDER_STYLE: Record<ProviderResult['result'], string> = {
  malicious: 'text-verdict-critical',
  suspicious: 'text-verdict-suspicious',
  clean: 'text-verdict-clean',
  unknown: 'text-content-muted',
  error: 'text-content-muted',
};

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li className="flex gap-3 border-b border-border-subtle py-3.5 last:border-0">
      <SeverityIcon severity={finding.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <p className="text-sm font-medium text-content-primary">{finding.title}</p>
          {finding.points > 0 && (
            <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-content-secondary">
              +{finding.points}
            </span>
          )}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-content-secondary">{finding.description}</p>
        {finding.mitre.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {finding.mitre.map((id) => (
              <span
                key={id}
                className="rounded border border-border-strong bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-content-muted"
              >
                {id}
              </span>
            ))}
          </div>
        )}
      </div>
    </li>
  );
}

function ScoreBreakdown({ scoring }: { scoring: Scoring }) {
  return (
    <div className="space-y-3">
      {scoring.breakdown.length > 0 ? (
        <ul className="space-y-1.5">
          {scoring.breakdown.map((entry) => (
            <li
              key={entry.code}
              className="flex items-center justify-between gap-3 text-sm text-content-secondary"
            >
              <span className="min-w-0 truncate">{entry.title}</span>
              <span className="shrink-0 font-medium tabular-nums text-content-primary">
                +{entry.points}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-content-secondary">
          No findings contributed points. Every check returned a benign or informational result.
        </p>
      )}

      <div className="space-y-1.5 border-t border-border-subtle pt-3 text-sm">
        <div className="flex justify-between text-content-secondary">
          <span>Heuristic points</span>
          <span className="tabular-nums">{scoring.base_points}</span>
        </div>
        {scoring.corroboration_bonus > 0 && (
          <div className="flex justify-between text-content-secondary">
            <span title="Independent high-severity findings agreeing with each other.">
              Corroboration bonus
            </span>
            <span className="tabular-nums">+{scoring.corroboration_bonus}</span>
          </div>
        )}
        {scoring.floor_applied > 0 && (
          <div className="flex justify-between text-content-secondary">
            <span title={scoring.floor_reason ?? undefined}>Minimum from identification</span>
            <span className="tabular-nums">{scoring.floor_applied}</span>
          </div>
        )}
        {scoring.capped_at_maximum && (
          <div className="flex justify-between text-content-muted">
            <span>Capped at maximum</span>
            <span className="tabular-nums">100</span>
          </div>
        )}
        <div className="flex justify-between border-t border-border-subtle pt-2 font-semibold text-content-primary">
          <span>Risk score</span>
          <span className="tabular-nums">{scoring.score} / 100</span>
        </div>
      </div>

      {scoring.floor_reason && (
        <p className="text-xs leading-relaxed text-content-muted">{scoring.floor_reason}</p>
      )}
    </div>
  );
}

/**
 * Content lifted out of a submitted sample, presented as evidence rather than
 * as part of the interface.
 *
 * Three properties matter here, and all three are deliberate:
 *
 * 1. **Never linkified.** These strings are attacker-authored. Rendering one
 *    as an `<a href>` would put a live route to hostile infrastructure one
 *    click away, inside a tool whose entire purpose is to avoid that.
 * 2. **Already defanged and scrubbed server-side.** `hxxp://` and `[.]` come
 *    from the backend; control characters and bidi overrides are stripped
 *    before storage. The UI does not re-derive safety, it inherits it.
 * 3. **Bounded.** Long lists are capped so a crafted sample cannot bloat the
 *    DOM or push the rest of the report off-screen.
 */
const EXTRACT_RENDER_CAP = 25;

function UntrustedList({ label, values }: { label: string; values: string[] }) {
  if (!values.length) return null;
  const shown = values.slice(0, EXTRACT_RENDER_CAP);
  return (
    <div>
      <p className="label-text mb-1.5">
        {label} <span className="normal-case">({values.length})</span>
      </p>
      <ul className="space-y-1">
        {shown.map((value, index) => (
          <li
            key={`${value}-${index}`}
            className="mono rounded border border-border-subtle bg-surface-2 px-2.5 py-1.5 text-content-secondary"
          >
            {value}
          </li>
        ))}
      </ul>
      {values.length > shown.length && (
        <p className="mt-1.5 text-xs text-content-muted">
          {values.length - shown.length} more not shown.
        </p>
      )}
    </div>
  );
}

function ExtractedContent({ analysis }: { analysis: Analysis }) {
  const indicators = analysis.details.embedded_indicators as Record<string, string[]> | undefined;
  const strings = analysis.details.sample_strings as string[] | undefined;

  const groups: { label: string; values: string[] }[] = [
    { label: 'URLs', values: indicators?.urls ?? [] },
    { label: 'IPv4 addresses', values: indicators?.ipv4 ?? [] },
    { label: 'Domains', values: indicators?.domains ?? [] },
    { label: 'Email addresses', values: indicators?.emails ?? [] },
    { label: 'Windows paths', values: indicators?.windows_paths ?? [] },
  ].filter((group) => group.values.length > 0);

  if (!groups.length && !strings?.length) return null;

  return (
    <Card
      title="Extracted content"
      description="Text taken verbatim from the sample. Treat it as hostile input, not as a reference."
    >
      <div className="mb-4">
        <InlineNotice tone="warning">
          Network indicators are shown <strong>defanged</strong> (<code>hxxp://</code>,{' '}
          <code>[.]</code>) and are deliberately not clickable. Do not visit them from a
          workstation.
        </InlineNotice>
      </div>

      <div className="space-y-4">
        {groups.map((group) => (
          <UntrustedList key={group.label} label={group.label} values={group.values} />
        ))}
        {strings && strings.length > 0 && <UntrustedList label="Sample strings" values={strings} />}
      </div>
    </Card>
  );
}

/** Renders the analyzer's technical detail dictionary, minus the scoring block. */
function TechnicalDetails({ analysis }: { analysis: Analysis }) {
  const {
    scoring: _scoring,
    // Rendered by <ExtractedContent /> with the untrusted-input framing that
    // a plain key/value row cannot convey.
    embedded_indicators: _embedded,
    sample_strings: _strings,
    ...rest
  } = analysis.details;
  const entries = Object.entries(rest).filter(([, value]) => value !== null && value !== '');

  return (
    <dl className="text-sm">
      <DefinitionRow label="Analysis reference">
        <span className="mono">{analysis.reference}</span>
      </DefinitionRow>
      <DefinitionRow label="Created">{formatDateTime(analysis.created_at)}</DefinitionRow>
      <DefinitionRow label="Analysis duration">
        {formatDuration(analysis.duration_seconds)}
      </DefinitionRow>
      <DefinitionRow label="Status">
        <StatusBadge status={analysis.status} />
      </DefinitionRow>

      {entries.map(([key, value]) => (
        <DefinitionRow key={key} label={humanizeKey(key)}>
          {typeof value === 'object' && value !== null && !Array.isArray(value) ? (
            <div className="space-y-1">
              {Object.entries(value as Record<string, unknown>).map(([nested, nestedValue]) => (
                <div key={nested} className="flex flex-wrap gap-x-2 text-xs">
                  <span className="text-content-muted">{humanizeKey(nested)}:</span>
                  <span className="mono text-content-secondary">
                    {formatDetailValue(nestedValue)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span className={typeof value === 'string' && value.length > 40 ? 'mono' : undefined}>
              {formatDetailValue(value)}
            </span>
          )}
        </DefinitionRow>
      ))}
    </dl>
  );
}

/* -------------------------------------------------------------------------- */

export default function Report() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const { data, loading, error, refresh } = useFetch(() => api.getAnalysis(id), [id]);

  async function handleDelete() {
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteAnalysis(id);
      navigate('/history');
    } catch (err) {
      // Previously a bare `finally`, so a refused delete failed in total
      // silence — the dialog just closed and the report stayed. On an instance
      // where deletion is the one gated action, that is the error the user is
      // most likely to hit.
      setDeleteError(
        err instanceof ApiError && err.status === 401
          ? 'Deleting requires an access token on this instance. Everything else stays open.'
          : err instanceof ApiError
            ? err.message
            : 'The report could not be deleted.',
      );
      setConfirming(false);
    } finally {
      setDeleting(false);
    }
  }

  if (loading) return <LoadingState label="Loading report…" />;
  if (error || !data) {
    return (
      <ErrorState
        title="Report unavailable"
        message={error?.message ?? 'That analysis could not be loaded.'}
        onRetry={refresh}
      />
    );
  }

  const scoring = data.details.scoring;
  const scored = [...data.findings]
    .filter((finding) => finding.points > 0)
    .sort((a, b) => b.points - a.points);
  const other = [...data.findings]
    .filter((finding) => finding.points === 0)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return (
    <>
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-sm text-content-secondary hover:text-content-primary"
        >
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" aria-hidden>
            <path
              d="m15 18-6-6 6-6"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            />
          </svg>
          Back to history
        </Link>

        {confirming ? (
          <div className="flex items-center gap-2 text-sm">
            <span className="text-content-secondary">Delete this report?</span>
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleting}
              className="btn border border-verdict-critical/40 bg-verdict-critical/10 px-3 py-1.5 text-xs text-verdict-critical hover:bg-verdict-critical/20"
            >
              {deleting ? 'Deleting…' : 'Confirm'}
            </button>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              className="btn-ghost px-3 py-1.5 text-xs"
            >
              Cancel
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-end gap-1">
            <button
              type="button"
              onClick={() => setConfirming(true)}
              className="btn-ghost px-3 py-1.5 text-xs"
            >
              Delete report
            </button>
            {deleteError && (
              <p role="alert" className="max-w-md text-right text-xs text-verdict-critical">
                {deleteError}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Verdict header */}
      <section className="card mb-5 overflow-hidden">
        <div className="flex flex-col items-center gap-7 p-6 sm:flex-row sm:items-start sm:p-7">
          <div className="text-center">
            <RiskGauge score={data.risk_score} verdict={data.verdict} />
            <p className="mt-3 text-[11px] tracking-widest text-content-muted uppercase">
              Risk Score
            </p>
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <VerdictBadge verdict={data.verdict} size="lg" />
              <IndicatorTypeBadge type={data.indicator_type} />
              {data.is_demo && <DemoBadge />}
            </div>

            <p className="mono mt-4 text-base text-content-primary">{data.indicator_display}</p>
            {data.indicator !== data.indicator_display && (
              <p className="mono mt-1.5 text-xs text-content-muted">{data.indicator}</p>
            )}

            {scoring && (
              <p className="mt-4 max-w-2xl text-sm leading-relaxed text-content-secondary">
                {scoring.summary}
              </p>
            )}

            <div className="mt-5 flex flex-wrap gap-x-8 gap-y-2 border-t border-border-subtle pt-4 text-xs">
              {[
                ['Reference', data.reference],
                ['Analysed', formatDateTime(data.created_at)],
                ['Duration', formatDuration(data.duration_seconds)],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-content-muted">{label}</p>
                  <p className="mt-0.5 font-medium text-content-primary">{value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="mb-5">
        <InlineNotice>
          <strong className="text-content-primary">Risk Score, not a malware probability.</strong>{' '}
          The score is a reproducible weighted sum of the documented heuristics listed below. It is
          not calibrated against a labelled corpus and should be read as a triage prioritisation
          aid, not as a statement of fact about the indicator.
        </InlineNotice>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <Card
            title="Why was this flagged?"
            description={
              scored.length
                ? `${scored.length} finding${scored.length === 1 ? '' : 's'} contributed to the risk score.`
                : 'No finding contributed points to the risk score.'
            }
          >
            {scored.length ? (
              <ul>
                {scored.map((finding) => (
                  <FindingRow key={finding.code} finding={finding} />
                ))}
              </ul>
            ) : (
              <p className="text-sm text-content-secondary">
                Every check returned a benign or informational result. Note that a clean verdict
                reflects the absence of detected indicators, which is not the same as proof of
                safety.
              </p>
            )}
          </Card>

          {other.length > 0 && (
            <Card
              title="Other observations"
              description="Checks that passed or returned context, contributing no points."
            >
              <ul>
                {other.map((finding) => (
                  <FindingRow key={finding.code} finding={finding} />
                ))}
              </ul>
            </Card>
          )}

          {data.mitre_techniques.length > 0 && (
            <Card
              title="MITRE ATT&CK — potential technique associations"
              description="Techniques commonly associated with the artefacts observed. Static evidence never proves a technique executed."
            >
              <ul className="space-y-3">
                {data.mitre_techniques.map((technique) => (
                  <li
                    key={technique.technique_id}
                    className="flex items-start gap-3 border-b border-border-subtle pb-3 last:border-0 last:pb-0"
                  >
                    <a
                      href={technique.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="mono shrink-0 rounded border border-accent/30 bg-accent/10 px-2 py-1 text-xs text-accent hover:bg-accent/20"
                    >
                      {technique.technique_id}
                    </a>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-content-primary">{technique.name}</p>
                      <p className="mt-0.5 text-xs text-content-muted">
                        Tactic: {technique.tactic} · {technique.confidence}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <ExtractedContent analysis={data} />

          <Card title="Technical details" description="Raw observations recorded by the analyzer.">
            <TechnicalDetails analysis={data} />
          </Card>
        </div>

        <div className="space-y-5">
          {scoring && (
            <Card title="Score breakdown" description="How the risk score was calculated.">
              <ScoreBreakdown scoring={scoring} />
            </Card>
          )}

          <Card
            title="Threat intelligence"
            description="Results from every enabled reputation provider."
          >
            {data.provider_results.length ? (
              <ul className="space-y-3">
                {data.provider_results.map((provider) => (
                  <li
                    key={provider.provider}
                    className="border-b border-border-subtle pb-3 last:border-0 last:pb-0"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium text-content-primary">
                        {provider.provider}
                      </span>
                      <span
                        className={`text-xs font-semibold uppercase ${PROVIDER_STYLE[provider.result]}`}
                      >
                        {provider.result}
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-content-secondary">
                      {provider.detail}
                    </p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-content-secondary">
                No threat-intelligence providers are enabled on this instance.
              </p>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
