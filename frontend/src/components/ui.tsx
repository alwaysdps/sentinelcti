/**
 * Shared presentational primitives.
 *
 * Grouped in one module because each is a handful of lines and they are always
 * imported together; splitting them into ten files would add navigation cost
 * without adding structure.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { AnalysisStatus, IndicatorType, Severity, Verdict } from '../types/analysis';
import { INDICATOR_LABEL, VERDICT_COLOR, VERDICT_LABEL } from '../lib/format';

/* -------------------------------------------------------------------------- */
/* Layout                                                                     */
/* -------------------------------------------------------------------------- */

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-content-primary">{title}</h1>
        {subtitle && <p className="mt-1.5 max-w-2xl text-sm text-content-secondary">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Card({
  title,
  description,
  actions,
  children,
  className = '',
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between gap-4 border-b border-border-subtle px-5 py-4">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-content-primary">{title}</h2>}
            {description && <p className="mt-1 text-xs text-content-muted">{description}</p>}
          </div>
          {actions}
        </div>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Status badges                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Verdict badge. Colour is reinforced with the written verdict so the meaning
 * survives for colour-blind users and in greyscale.
 */
export function VerdictBadge({ verdict, size = 'sm' }: { verdict: Verdict; size?: 'sm' | 'lg' }) {
  const color = VERDICT_COLOR[verdict];
  const padding = size === 'lg' ? 'px-3.5 py-1.5 text-sm' : 'px-2.5 py-1 text-xs';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${padding}`}
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}14` }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

const SEVERITY_STYLE: Record<Severity, { label: string; className: string; glyph: string }> = {
  high: { label: 'High', className: 'text-verdict-critical', glyph: '!' },
  medium: { label: 'Medium', className: 'text-verdict-high', glyph: '!' },
  low: { label: 'Low', className: 'text-verdict-suspicious', glyph: '•' },
  info: { label: 'Info', className: 'text-content-muted', glyph: 'i' },
  pass: { label: 'Pass', className: 'text-verdict-clean', glyph: '✓' },
};

export function SeverityIcon({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span
      className={`inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-current/25 bg-current/10 text-xs font-bold ${style.className}`}
      title={`${style.label} severity`}
      aria-label={`${style.label} severity`}
    >
      {style.glyph}
    </span>
  );
}

export function IndicatorTypeBadge({ type }: { type: IndicatorType }) {
  return (
    <span className="inline-flex items-center rounded-full border border-border-subtle bg-surface-2 px-2.5 py-0.5 text-[11px] font-medium text-content-secondary">
      {INDICATOR_LABEL[type]}
    </span>
  );
}

export function StatusBadge({ status }: { status: AnalysisStatus }) {
  const copy: Record<AnalysisStatus, { label: string; hint: string; className: string }> = {
    completed: {
      label: 'Completed',
      hint: 'All analysis steps finished.',
      className: 'text-verdict-clean',
    },
    partial: {
      label: 'Partial',
      hint: 'Analysis completed, but an optional enrichment step returned no data.',
      className: 'text-verdict-suspicious',
    },
    failed: {
      label: 'Failed',
      hint: 'Analysis did not complete.',
      className: 'text-verdict-critical',
    },
  };
  const entry = copy[status];
  return (
    <span className={`text-xs font-medium ${entry.className}`} title={entry.hint}>
      {entry.label}
    </span>
  );
}

/** Marks synthetic seed rows so demo data is never mistaken for real intel. */
export function DemoBadge() {
  return (
    <span
      className="inline-flex items-center rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold tracking-wide text-accent uppercase"
      title="Synthetic demo data created by the seed script — not real threat intelligence."
    >
      Demo
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Async states                                                               */
/* -------------------------------------------------------------------------- */

export function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M12 2a10 10 0 0 1 10 10h-3a7 7 0 0 0-7-7V2Z"
      />
    </svg>
  );
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 py-16 text-content-muted"
      role="status"
    >
      <Spinner className="h-7 w-7 text-accent" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-14 text-center" role="alert">
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-verdict-critical/40 bg-verdict-critical/10 text-lg text-verdict-critical">
        !
      </div>
      <div>
        <p className="text-sm font-semibold text-content-primary">{title}</p>
        <p className="mx-auto mt-1 max-w-md text-sm text-content-secondary">{message}</p>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="btn-secondary mt-1">
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  message,
  action,
}: {
  title: string;
  message: string;
  action?: { label: string; to: string };
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-border-strong bg-surface-2 text-content-muted">
        <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5" aria-hidden>
          <path
            d="M4 6h16M4 12h16M4 18h10"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      </div>
      <div>
        <p className="text-sm font-semibold text-content-primary">{title}</p>
        <p className="mx-auto mt-1 max-w-md text-sm text-content-secondary">{message}</p>
      </div>
      {action && (
        <Link to={action.to} className="btn-primary mt-1">
          {action.label}
        </Link>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Small utilities                                                            */
/* -------------------------------------------------------------------------- */

export function DefinitionRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border-subtle py-3 last:border-0 sm:flex-row sm:gap-4">
      <dt className="w-full shrink-0 text-xs font-medium text-content-muted sm:w-52">{label}</dt>
      <dd className="min-w-0 flex-1 text-sm text-content-primary">{children}</dd>
    </div>
  );
}

export function InlineNotice({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning';
  children: ReactNode;
}) {
  const styles =
    tone === 'warning'
      ? 'border-verdict-suspicious/35 bg-verdict-suspicious/10 text-verdict-suspicious'
      : 'border-accent/30 bg-accent/8 text-content-secondary';
  return (
    <div className={`rounded-lg border px-4 py-3 text-xs leading-relaxed ${styles}`}>
      {children}
    </div>
  );
}
