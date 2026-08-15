/**
 * Shell and prose primitives for the policy documents.
 *
 * Clauses are numbered and individually anchored so a specific paragraph can be
 * cited — "clause 6" has to mean one thing, which it does not if the numbering
 * lives in prose and drifts on the next edit. The page derives both the
 * contents list and the numbering from a single array, so they cannot disagree.
 *
 * Styled with explicit classes rather than a typography plugin: the project
 * carries no such dependency, and a handful of primitives is smaller than one.
 */

import { useEffect, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { SiteFooter, SiteHeader } from '../../components/SiteChrome';
import { LAST_UPDATED } from './legalMeta';

export interface Clause {
  id: string;
  title: string;
  body: ReactNode;
}

/* -------------------------------------------------------------------------- */
/* Prose primitives                                                           */
/* -------------------------------------------------------------------------- */

export function P({ children }: { children: ReactNode }) {
  return <p className="mt-4 text-sm leading-relaxed text-content-secondary">{children}</p>;
}

export function Bullets({ children }: { children: ReactNode }) {
  return (
    <ul className="mt-4 space-y-2.5 text-sm leading-relaxed text-content-secondary">{children}</ul>
  );
}

export function Bullet({ children }: { children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span aria-hidden className="mt-2 h-1 w-1 shrink-0 rounded-full bg-content-muted" />
      <span className="min-w-0">{children}</span>
    </li>
  );
}

/** Bolded lead-in for a defined term, kept visually distinct from body copy. */
export function Term({ children }: { children: ReactNode }) {
  return <strong className="font-medium text-content-primary">{children}</strong>;
}

export function Callout({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warning';
  children: ReactNode;
}) {
  const styles =
    tone === 'warning'
      ? 'border-verdict-suspicious/30 bg-verdict-suspicious/10 text-verdict-suspicious'
      : 'border-border-strong bg-surface-2 text-content-secondary';
  return (
    <div className={`mt-5 rounded-xl border px-4 py-3.5 text-sm leading-relaxed ${styles}`}>
      {children}
    </div>
  );
}

/**
 * Two-column table for "what is stored / how long" style disclosures.
 *
 * `label` is a node rather than a string because several rows name a storage
 * key in monospace; `key` therefore comes from an explicit `id`.
 */
export function FactTable({ rows }: { rows: { id: string; label: ReactNode; value: ReactNode }[] }) {
  return (
    <dl className="mt-5 divide-y divide-border-subtle rounded-xl border border-border-subtle">
      {rows.map((row) => (
        <div key={row.id} className="flex flex-col gap-1.5 px-4 py-3.5 sm:flex-row sm:gap-6">
          <dt className="w-full shrink-0 text-sm font-medium text-content-primary sm:w-64">
            {row.label}
          </dt>
          <dd className="min-w-0 flex-1 text-sm leading-relaxed text-content-secondary">
            {row.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono text-content-primary">{children}</code>;
}

/* -------------------------------------------------------------------------- */
/* Page shell                                                                 */
/* -------------------------------------------------------------------------- */

export default function LegalPage({
  title,
  intro,
  summary,
  clauses,
}: {
  title: string;
  /** One sentence under the heading, describing what the document covers. */
  intro: string;
  /** Plain-English précis. Present because nobody reads the numbered part. */
  summary: ReactNode;
  clauses: Clause[];
}) {
  // Anchored deep links must land on the clause, not wherever the previous
  // page was scrolled to — the router preserves scroll position across
  // navigations, which puts a fresh policy page mid-document.
  useEffect(() => {
    if (!window.location.hash) window.scrollTo(0, 0);
  }, []);

  return (
    <div className="min-h-screen bg-surface-0">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-surface-2 focus:px-4 focus:py-2 focus:text-sm"
      >
        Skip to content
      </a>

      <SiteHeader />

      <main id="main-content" className="mx-auto max-w-6xl px-5 py-12 sm:px-8 sm:py-16">
        <header className="max-w-3xl">
          <p className="label-text">Legal</p>
          <h1 className="mt-3 text-3xl leading-tight font-light tracking-tight text-content-primary sm:text-4xl">
            {title}
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-content-secondary">{intro}</p>
          <p className="mt-4 text-xs text-content-muted">Last updated {LAST_UPDATED}</p>
        </header>

        <div className="mt-10 grid gap-10 lg:grid-cols-[minmax(0,1fr)_240px] lg:gap-14">
          <div className="order-2 min-w-0 lg:order-1">
            <section className="card-padded" aria-labelledby="summary-heading">
              <h2 id="summary-heading" className="label-text">
                In short
              </h2>
              <div className="mt-3">{summary}</div>
              <p className="mt-4 text-xs leading-relaxed text-content-muted">
                This summary is for orientation only. Where it and the numbered clauses differ, the
                clauses govern.
              </p>
            </section>

            <div className="mt-10 space-y-12">
              {clauses.map((clause, index) => (
                <section key={clause.id} id={clause.id} className="scroll-mt-24">
                  <h2 className="flex gap-3 text-lg font-semibold tracking-tight text-content-primary">
                    <span className="font-mono text-sm text-accent tabular-nums">{index + 1}</span>
                    {clause.title}
                  </h2>
                  {clause.body}
                </section>
              ))}
            </div>

            <div className="mt-14 border-t border-border-subtle pt-6">
              <p className="text-xs leading-relaxed text-content-muted">
                SentinelCTI is a demonstration and portfolio project. These documents are written to
                describe the system accurately; they are not legal advice, and an operator deploying
                this software for anything beyond demonstration should have them reviewed by a
                qualified adviser for their own circumstances.
              </p>
            </div>
          </div>

          {/* Contents. Ordered before the body on small screens would push the
              document down a full viewport, so it is source-ordered second and
              re-ordered into the sidebar only where there is room for it. */}
          <nav
            className="order-1 lg:sticky lg:top-24 lg:order-2 lg:self-start"
            aria-label="Document contents"
          >
            <p className="label-text">Contents</p>
            <ol className="mt-3 space-y-2">
              {clauses.map((clause, index) => (
                <li key={clause.id} className="flex gap-2.5 text-sm">
                  <span className="font-mono text-xs text-content-muted tabular-nums">
                    {index + 1}
                  </span>
                  <a
                    href={`#${clause.id}`}
                    className="text-content-secondary transition-colors hover:text-content-primary"
                  >
                    {clause.title}
                  </a>
                </li>
              ))}
            </ol>

            <div className="mt-6 border-t border-border-subtle pt-4">
              <Link to="/privacy" className="block text-sm text-content-secondary hover:text-accent">
                Privacy policy
              </Link>
              <Link
                to="/terms"
                className="mt-2 block text-sm text-content-secondary hover:text-accent"
              >
                Terms of service
              </Link>
            </div>
          </nav>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
