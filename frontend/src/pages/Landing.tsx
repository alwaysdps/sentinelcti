/**
 * Public front page.
 *
 * The first thing a visitor sees is no longer the console. A dashboard opens on
 * aggregate numbers, which only mean something once you already know what the
 * platform does and what it refuses to do — so this page answers those two
 * questions first and then hands over to the console.
 *
 * Every claim below is one the application actually implements, and each is
 * phrased the way the reports are: specific, and honest about the limits.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { SiteFooter, SiteHeader } from '../components/SiteChrome';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';
import { VERDICT_COLOR } from '../lib/format';

/* -------------------------------------------------------------------------- */
/* Page furniture                                                             */
/* -------------------------------------------------------------------------- */

function Section({
  id,
  eyebrow,
  title,
  lede,
  children,
}: {
  id?: string;
  eyebrow: string;
  title: ReactNode;
  lede?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-24 border-t border-border-subtle py-16 sm:py-20">
      <div className="mx-auto max-w-6xl px-5 sm:px-8">
        <p className="label-text">{eyebrow}</p>
        <h2 className="mt-3 max-w-3xl text-2xl leading-tight font-light tracking-tight text-content-primary sm:text-3xl">
          {title}
        </h2>
        {lede && <p className="mt-4 max-w-2xl text-sm leading-relaxed text-content-secondary">{lede}</p>}
        <div className="mt-10">{children}</div>
      </div>
    </section>
  );
}

/** Live backend state, shown as the hero eyebrow rather than a claim in prose. */
function StatusPill() {
  const { data, error, loading } = useFetch(() => api.health(), []);

  const state = loading
    ? { color: 'bg-content-muted', label: 'Checking engine…' }
    : error || data?.status !== 'ok'
      ? { color: 'bg-verdict-suspicious', label: 'Engine unreachable' }
      : {
          color: 'bg-accent',
          label: `Engine operational · ${data.analyses_stored.toLocaleString()} analyses stored`,
        };

  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-border-subtle bg-surface-1 px-3.5 py-1.5 text-xs text-content-secondary">
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${state.color}`} aria-hidden />
      {state.label}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Hero                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The example report.
 *
 * Reproduced from a real submission rather than invented for the page: the same
 * URL through /analyze/url returns these findings and this total. The host is an
 * RFC 2606 `.example` name, so it resolves nowhere, and it is rendered as text —
 * never a link, which is the same rule the reports follow.
 */
const EXAMPLE_FINDINGS: { severity: 'high' | 'medium' | 'low' | 'pass'; title: string; points: string; attack?: string }[] = [
  {
    severity: 'high',
    title: 'Brand name in subdomain (paypal)',
    points: '+25',
    attack: 'T1566.002, T1036',
  },
  {
    severity: 'medium',
    title: 'Credential-themed keywords in host (account, login)',
    points: '+15',
    attack: 'T1566.002',
  },
  { severity: 'low', title: 'Plaintext HTTP', points: '+10' },
  { severity: 'pass', title: 'Valid hostname syntax', points: '—' },
];

const SEVERITY_MARK: Record<string, { glyph: string; color: string }> = {
  high: { glyph: '!', color: VERDICT_COLOR.critical },
  medium: { glyph: '!', color: VERDICT_COLOR.high_risk },
  low: { glyph: '•', color: VERDICT_COLOR.suspicious },
  pass: { glyph: '✓', color: VERDICT_COLOR.clean },
};

function ExampleReport() {
  return (
    <figure className="card overflow-hidden">
      <div className="flex items-center justify-between gap-4 border-b border-border-subtle px-5 py-3.5">
        <div className="flex items-center gap-2">
          <span className="label-text">Example report</span>
        </div>
        <span
          className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium"
          style={{
            color: VERDICT_COLOR.suspicious,
            borderColor: `${VERDICT_COLOR.suspicious}55`,
            backgroundColor: `${VERDICT_COLOR.suspicious}14`,
          }}
        >
          <span
            aria-hidden
            className="h-1.5 w-1.5 rounded-full"
            style={{ backgroundColor: VERDICT_COLOR.suspicious }}
          />
          Suspicious
        </span>
      </div>

      <div className="px-5 py-4">
        <p className="label-text">Indicator</p>
        <p className="mono mt-1.5 text-content-primary">
          http://secure-login.paypal.account-verify.example/session/renew
        </p>

        <div className="mt-5 flex items-baseline gap-2">
          <span className="text-3xl font-semibold tabular-nums text-content-primary">50</span>
          <span className="text-sm text-content-muted">/ 100 risk score</span>
        </div>
        <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-surface-3">
          <div
            className="h-full rounded-full"
            style={{ width: '50%', backgroundColor: VERDICT_COLOR.suspicious }}
          />
        </div>
      </div>

      <div className="border-t border-border-subtle px-5 py-4">
        <p className="label-text mb-3">Why was this flagged?</p>
        <ul className="space-y-2.5">
          {EXAMPLE_FINDINGS.map((finding) => {
            const mark = SEVERITY_MARK[finding.severity];
            return (
              <li key={finding.title} className="flex items-start gap-3">
                <span
                  className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold"
                  style={{ color: mark.color, backgroundColor: `${mark.color}1a` }}
                  aria-hidden
                >
                  {mark.glyph}
                </span>
                <span className="min-w-0 flex-1 text-sm text-content-secondary">
                  {finding.title}
                  {finding.attack && (
                    <span className="ml-2 font-mono text-[11px] text-content-muted">
                      {finding.attack}
                    </span>
                  )}
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums text-content-muted">
                  {finding.points}
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      <figcaption className="border-t border-border-subtle px-5 py-3 text-[11px] leading-relaxed text-content-muted">
        Reproducible: submitting the same URL returns the same findings and the same total. The
        score is a documented weighted sum, not a probability.
      </figcaption>
    </figure>
  );
}

function Hero() {
  return (
    <div className="relative overflow-hidden">
      {/* A single soft emission behind the headline. The palette spends its
          chroma on status, so the page itself gets one light source, not a
          decorative gradient wash. */}
      <div
        aria-hidden
        className="pointer-events-none absolute -top-40 left-1/2 h-[36rem] w-[64rem] -translate-x-1/2"
        style={{
          background:
            'radial-gradient(closest-side, var(--color-accent-glow), transparent 70%)',
          opacity: 0.55,
        }}
      />

      <div className="relative mx-auto max-w-6xl px-5 py-16 sm:px-8 sm:py-24">
        <div className="grid items-center gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,480px)] lg:gap-16">
          <div>
            <StatusPill />

            <h1 className="mt-6 text-4xl leading-[1.05] font-light tracking-tight text-content-primary sm:text-5xl lg:text-6xl">
              Know what you are
              <br />
              <span className="font-semibold">actually looking at.</span>
            </h1>

            <p className="mt-6 max-w-xl text-base leading-relaxed text-content-secondary">
              SentinelCTI triages suspicious files, URLs, domains, IP addresses and hashes on
              infrastructure you control — and shows you every point of reasoning behind the
              verdict, instead of a number you have to take on faith.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link to="/analyze" className="btn-primary">
                Analyze an indicator
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" aria-hidden>
                  <path
                    d="M5 12h14m-6-6 6 6-6 6"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </Link>
              <Link to="/dashboard" className="btn-secondary">
                Open the console
              </Link>
            </div>

            <p className="mt-6 text-xs text-content-muted">
              No account · No API keys · Works with no internet access at all
            </p>
          </div>

          <ExampleReport />
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Content sections                                                           */
/* -------------------------------------------------------------------------- */

const PILLARS = [
  {
    title: 'Runs where you run it',
    body: 'The default configuration needs no API keys and no outbound connectivity. Nothing you submit is uploaded to a third party, because there is no third party in the path.',
    path: 'M4 7v10l8 4 8-4V7l-8-4-8 4Zm8 4v10',
  },
  {
    title: 'Shows its arithmetic',
    body: 'There is no opaque score. Every point belongs to a named check with a written rationale, and the report prints the sum — including when a score floor lifted it.',
    path: 'M4 19V5m0 14h16M8 15v-4m4 4V8m4 7v-6',
  },
  {
    title: 'Never touches the target',
    body: 'Files are not executed. URLs are not fetched. IP addresses are not contacted. Analysis is strictly static, and DNS resolution — off by default — goes to your resolver, never the indicator.',
    path: 'M12 3 4 7v5c0 5 3.4 9.4 8 10 4.6-.6 8-5 8-10V7l-8-4Zm-4 8h8',
  },
];

const ANALYZERS = [
  {
    label: 'URL',
    to: '/analyze/url',
    body: 'Brand names in subdomains the brand does not own, credential keywords, embedded credentials, nested URLs, punycode, heavy percent-encoding, payload extensions and abuse-prone TLDs.',
  },
  {
    label: 'Domain',
    to: '/analyze/domain',
    body: 'Registrable-domain decomposition against a curated public-suffix set, Shannon entropy on the second-level label to surface DGA-like names, digit and hyphen density.',
  },
  {
    label: 'IP address',
    to: '/analyze/ip',
    body: 'Scope classification against the IANA special-purpose registries, separating documentation ranges from RFC 1918 space, plus IPv4-mapped and Teredo detection.',
  },
  {
    label: 'File hash',
    to: '/analyze/hash',
    body: 'Algorithm identification with the collision-resistance caveat stated, recognition of well-known digests, and provider lookup where one is configured.',
  },
  {
    label: 'File',
    to: '/analyze/file',
    body: 'Type identified from magic bytes rather than the extension, entropy for packing, string extraction, ~18 suspicious-pattern families, and the indicators embedded inside.',
  },
];

const GUARANTEES = [
  {
    claim: 'Uploaded files are never executed',
    how: 'The file analyzer only ever calls open(path, "rb"). No subprocess, no interpreter, no archive extraction.',
  },
  {
    claim: 'Uploads are never web-reachable',
    how: 'Quarantine lives outside every static mount, under a random name. No route returns file bytes.',
  },
  {
    claim: 'Uploads are not retained',
    how: 'Bytes are deleted in a finally block after analysis — even when analysis raised. Hashes and metadata remain.',
  },
  {
    claim: 'Submitted URLs are never requested',
    how: 'URL analysis is pure parsing. Active fetching sits behind a setting that is off by default.',
  },
  {
    claim: 'A hostile sample cannot exhaust the service',
    how: 'Bounded, linear-by-construction extraction, a cooperative deadline, a concurrency gate and a disk ceiling.',
  },
  {
    claim: 'Sample content cannot deceive the operator',
    how: 'Extracted text is stripped of control characters and bidi overrides; network indicators are defanged and never linked.',
  },
];

const PIPELINE = [
  {
    step: '01',
    title: 'Validate',
    body: 'Pydantic checks the submission at the boundary, with explicit length bounds, before anything else runs.',
  },
  {
    step: '02',
    title: 'Observe',
    body: 'The analyzer emits named signals — one explainable observation each. Analyzers never compute a score; that separation is what makes the number auditable.',
  },
  {
    step: '03',
    title: 'Corroborate',
    body: 'Threat-intelligence providers are queried concurrently and failure-isolated. A slow or broken provider marks the analysis partial; it cannot fail it.',
  },
  {
    step: '04',
    title: 'Score',
    body: 'The risk engine accumulates signal points, adds a corroboration bonus for independent agreement, and applies score floors so a positive identification outranks a pile of weak heuristics.',
  },
];

const BANDS = [
  { range: '0–19', label: 'Clean', color: VERDICT_COLOR.clean, meaning: 'No meaningful risk indicators found.' },
  { range: '20–49', label: 'Low Risk', color: VERDICT_COLOR.low_risk, meaning: 'Minor or ambiguous indicators.' },
  { range: '50–69', label: 'Suspicious', color: VERDICT_COLOR.suspicious, meaning: 'Multiple indicators warrant review.' },
  { range: '70–89', label: 'High Risk', color: VERDICT_COLOR.high_risk, meaning: 'Strong indicators of malicious intent.' },
  { range: '90–100', label: 'Critical', color: VERDICT_COLOR.critical, meaning: 'Severe, corroborated indicators.' },
];

/* -------------------------------------------------------------------------- */

export default function Landing() {
  return (
    <div className="min-h-screen bg-surface-0">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-surface-2 focus:px-4 focus:py-2 focus:text-sm"
      >
        Skip to content
      </a>

      <SiteHeader
        sections={[
          { href: '#capabilities', label: 'Capabilities' },
          { href: '#safety', label: 'Safety' },
          { href: '#method', label: 'Method' },
        ]}
      />

      <main id="main-content">
        <Hero />

        {/* Pillars: the three properties that distinguish this from pasting an
            indicator into a public scanner. */}
        <section className="border-t border-border-subtle py-16 sm:py-20">
          <div className="mx-auto grid max-w-6xl gap-8 px-5 sm:px-8 lg:grid-cols-3">
            {PILLARS.map((pillar) => (
              <div key={pillar.title}>
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-accent/25 bg-accent/10 text-accent">
                  <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
                    <path
                      d={pillar.path}
                      stroke="currentColor"
                      strokeWidth="1.6"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
                <h3 className="mt-4 text-base font-semibold text-content-primary">{pillar.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-content-secondary">{pillar.body}</p>
              </div>
            ))}
          </div>
        </section>

        <Section
          id="capabilities"
          eyebrow="Capabilities"
          title={
            <>
              Five indicator types,{' '}
              <span className="font-semibold">one explainable pipeline.</span>
            </>
          }
          lede="Each analyzer observes; none of them score. What they produce is a list of named findings, which is what the report is built from."
        >
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {ANALYZERS.map((analyzer) => (
              <Link
                key={analyzer.label}
                to={analyzer.to}
                className="card group p-5 transition-colors hover:border-border-strong"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-content-primary">
                    {analyzer.label}
                  </span>
                  <svg
                    viewBox="0 0 24 24"
                    className="h-4 w-4 text-content-muted transition-colors group-hover:text-accent"
                    fill="none"
                    aria-hidden
                  >
                    <path
                      d="M7 17 17 7m0 0H8m9 0v9"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
                <p className="mt-2.5 text-sm leading-relaxed text-content-secondary">
                  {analyzer.body}
                </p>
              </Link>
            ))}

            <div className="card flex flex-col justify-between p-5">
              <div>
                <span className="text-sm font-semibold text-content-primary">MITRE ATT&CK</span>
                <p className="mt-2.5 text-sm leading-relaxed text-content-secondary">
                  Findings carry technique IDs, resolved into a section labelled{' '}
                  <em className="not-italic text-content-primary">
                    potential technique association
                  </em>
                  . A string in a file shows a capability is referenced — never that it executed.
                </p>
              </div>
            </div>
          </div>
        </Section>

        <Section
          id="safety"
          eyebrow="Safety model"
          title={
            <>
              The analyzer handles hostile input.{' '}
              <span className="font-semibold">Every guarantee is enforced in code.</span>
            </>
          }
          lede="This is the section to read first, because the rest of the design follows from it. Each row below is held shut by a test."
        >
          <div className="card divide-y divide-border-subtle">
            {GUARANTEES.map((item) => (
              <div key={item.claim} className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:gap-6">
                <div className="flex min-w-0 flex-1 items-start gap-3">
                  <svg
                    viewBox="0 0 24 24"
                    className="mt-0.5 h-4 w-4 shrink-0 text-accent"
                    fill="none"
                    aria-hidden
                  >
                    <path
                      d="m5 13 4 4L19 7"
                      stroke="currentColor"
                      strokeWidth="2.2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  <span className="text-sm font-medium text-content-primary">{item.claim}</span>
                </div>
                <p className="flex-1 text-sm leading-relaxed text-content-muted sm:max-w-md">
                  {item.how}
                </p>
              </div>
            ))}
          </div>

          <p className="mt-6 max-w-3xl text-sm leading-relaxed text-content-secondary">
            Not implemented, deliberately: malware detonation, credential harvesting, persistence,
            exploitation, vulnerability scanning or unauthorised network scanning. This platform
            analyses indicators. It does not attack anything.
          </p>
        </Section>

        <Section
          id="method"
          eyebrow="Method"
          title={
            <>
              From submission to a number{' '}
              <span className="font-semibold">you can argue with.</span>
            </>
          }
        >
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {PIPELINE.map((stage) => (
              <div key={stage.step} className="border-t border-border-strong pt-4">
                <span className="font-mono text-xs text-accent">{stage.step}</span>
                <h3 className="mt-2 text-sm font-semibold text-content-primary">{stage.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-content-secondary">{stage.body}</p>
              </div>
            ))}
          </div>

          <div className="card mt-10 p-5">
            <p className="label-text mb-4">Score bands</p>
            <ul className="space-y-3">
              {BANDS.map((band) => (
                <li key={band.label} className="flex flex-wrap items-center gap-x-4 gap-y-1">
                  <span className="w-16 shrink-0 font-mono text-xs tabular-nums text-content-muted">
                    {band.range}
                  </span>
                  <span
                    className="inline-flex w-28 shrink-0 items-center gap-2 text-sm font-medium"
                    style={{ color: band.color }}
                  >
                    <span
                      aria-hidden
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ backgroundColor: band.color }}
                    />
                    {band.label}
                  </span>
                  <span className="min-w-0 flex-1 text-sm text-content-secondary">
                    {band.meaning}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-6 rounded-lg border border-verdict-suspicious/30 bg-verdict-suspicious/10 px-4 py-3 text-xs leading-relaxed text-verdict-suspicious">
            It is a risk score, not a malware probability. The number is a reproducible weighted sum
            of documented heuristics, not a figure calibrated against a labelled corpus — and a
            Clean verdict reflects the absence of detected indicators, which is not proof of safety.
          </div>
        </Section>

        {/* Closing call to action. */}
        <section className="border-t border-border-subtle py-16 sm:py-20">
          <div className="mx-auto max-w-6xl px-5 sm:px-8">
            <div className="card-padded flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-center">
              <div>
                <h2 className="text-xl font-semibold tracking-tight text-content-primary">
                  Have something to triage?
                </h2>
                <p className="mt-2 max-w-xl text-sm leading-relaxed text-content-secondary">
                  Paste a URL, domain, IP address or hash — or upload a file. Nothing is executed,
                  nothing is fetched, and the report tells you exactly why it landed where it did.
                </p>
              </div>
              <Link to="/analyze" className="btn-primary shrink-0">
                Analyze an indicator
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
