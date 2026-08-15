/**
 * Public-site header and footer.
 *
 * Shared by the front page and the legal pages so the two cannot drift: a
 * footer that lists the policies is exactly the thing that gets forgotten on
 * the pages the policies live on.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Logo } from './Brand';

export interface SectionLink {
  href: string;
  label: string;
}

export function SiteHeader({ sections = [] }: { sections?: SectionLink[] }) {
  return (
    <header className="sticky top-0 z-30 border-b border-border-subtle bg-surface-0/85 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-5 py-3.5 sm:px-8">
        <Link to="/" aria-label="SentinelCTI home">
          <Logo />
        </Link>

        {sections.length > 0 && (
          <nav className="hidden items-center gap-1 md:flex" aria-label="Page sections">
            {sections.map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="rounded-full px-3.5 py-2 text-sm text-content-secondary transition-colors hover:bg-surface-2 hover:text-content-primary"
              >
                {item.label}
              </a>
            ))}
          </nav>
        )}

        <Link to="/dashboard" className="btn-primary shrink-0 px-4 py-2">
          Open console
        </Link>
      </div>
    </header>
  );
}

function FooterLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="text-content-secondary transition-colors hover:text-content-primary">
      {children}
    </Link>
  );
}

export function SiteFooter() {
  return (
    <footer className="border-t border-border-subtle py-10">
      <div className="mx-auto max-w-6xl px-5 sm:px-8">
        <div className="flex flex-col gap-8 md:flex-row md:justify-between">
          <div>
            <Logo />
            <p className="mt-3 max-w-md text-xs leading-relaxed text-content-muted">
              A defensive threat-intelligence platform. Do not upload confidential data — this is a
              demonstration platform, not an accredited malware analysis service.
            </p>
          </div>

          <div className="flex gap-12">
            <nav className="flex flex-col gap-2 text-sm" aria-label="Console">
              <p className="label-text mb-1">Console</p>
              <FooterLink to="/dashboard">Dashboard</FooterLink>
              <FooterLink to="/analyze">Analyze</FooterLink>
              <FooterLink to="/history">History</FooterLink>
              <FooterLink to="/settings">Settings</FooterLink>
            </nav>

            <nav className="flex flex-col gap-2 text-sm" aria-label="Legal and reference">
              <p className="label-text mb-1">Legal</p>
              <FooterLink to="/privacy">Privacy policy</FooterLink>
              <FooterLink to="/terms">Terms of service</FooterLink>
              <a
                href="/docs"
                className="text-content-secondary transition-colors hover:text-content-primary"
              >
                API docs
              </a>
            </nav>
          </div>
        </div>

        <div className="mt-10 flex flex-col gap-2 border-t border-border-subtle pt-6 text-xs text-content-muted sm:flex-row sm:items-center sm:justify-between">
          <p>© {new Date().getFullYear()} SentinelCTI. Source released under the MIT Licence.</p>
          <p>Defensive analysis only · Files are never executed · URLs are never fetched</p>
        </div>
      </div>
    </footer>
  );
}
