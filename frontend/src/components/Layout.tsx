/** Application shell: sidebar navigation, header and content region. */

import { useEffect, useState, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

const icon = (path: string) => (
  <svg viewBox="0 0 24 24" fill="none" className="h-[18px] w-[18px]" aria-hidden>
    <path
      d={path}
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const NAV_ITEMS: NavItem[] = [
  {
    to: '/dashboard',
    label: 'Dashboard',
    icon: icon('M4 13h6V4H4v9Zm0 7h6v-4H4v4Zm10 0h6v-9h-6v9Zm0-16v4h6V4h-6Z'),
  },
  {
    to: '/analyze',
    label: 'Analyze',
    icon: icon('m21 21-4.35-4.35M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16Z'),
  },
  {
    to: '/history',
    label: 'History',
    icon: icon('M12 8v4l3 2m6-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z'),
  },
  {
    to: '/settings',
    label: 'Settings',
    icon: icon(
      'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.1l2-1.6-2-3.4-2.4 1a7.5 7.5 0 0 0-1.9-1.1L14.6 2h-3.9l-.4 2.8c-.7.3-1.3.6-1.9 1.1l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.2l-2 1.6 2 3.4 2.4-1c.6.5 1.2.8 1.9 1.1l.4 2.8h3.9l.4-2.8c.7-.3 1.3-.6 1.9-1.1l2.4 1 2-3.4-2-1.6c0-.4.1-.7.1-1.1Z',
    ),
  },
];

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" className="h-7 w-7 text-accent" aria-hidden>
        <path
          fill="currentColor"
          d="M16 2 4 7v9c0 7.2 5.1 13.9 12 15.5C22.9 29.9 28 23.2 28 16V7L16 2Zm0 3.3 9 3.7v7c0 5.7-3.8 11-9 12.5C10.8 27 7 21.7 7 16V9l9-3.7Z"
        />
        <path fill="currentColor" d="M14.6 19.4 11 15.8l1.8-1.8 1.8 1.8 4.6-4.6 1.8 1.8-6.4 6.4Z" />
      </svg>
      <div className="leading-tight">
        <p className="text-sm font-semibold tracking-tight text-content-primary">SentinelCTI</p>
        <p className="text-[10px] tracking-widest text-content-muted uppercase">Threat Intel</p>
      </div>
    </div>
  );
}

/** Live backend reachability, shown in the sidebar footer. */
function HealthIndicator() {
  const { data, error, loading } = useFetch(() => api.health(), []);

  const state = loading
    ? { color: 'bg-content-muted', label: 'Checking backend…' }
    : error || data?.status !== 'ok'
      ? { color: 'bg-verdict-critical', label: 'Backend unreachable' }
      : { color: 'bg-verdict-clean', label: `Operational · v${data.version}` };

  return (
    <div className="flex items-center gap-2 px-3 py-2 text-xs text-content-muted">
      <span className={`h-2 w-2 shrink-0 rounded-full ${state.color}`} aria-hidden />
      <span className="truncate">{state.label}</span>
    </div>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <div className="px-5 py-5">
        <Logo />
      </div>

      <nav className="flex-1 space-y-1 px-3" aria-label="Main navigation">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-accent/12 text-accent'
                  : 'text-content-secondary hover:bg-surface-2 hover:text-content-primary'
              }`
            }
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border-subtle px-2 py-2">
        <HealthIndicator />
        <p className="px-3 pb-2 text-[10px] leading-relaxed text-content-muted">
          Defensive analysis only. Files are never executed and URLs are never fetched.
        </p>
      </div>
    </div>
  );
}

export default function Layout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  // Route changes should dismiss the mobile drawer, otherwise it covers the
  // page the user just navigated to.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  return (
    <div className="min-h-screen bg-surface-0">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-surface-2 focus:px-4 focus:py-2 focus:text-sm"
      >
        Skip to content
      </a>

      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r border-border-subtle bg-surface-1 lg:block">
        <SidebarContent />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-black/60"
            onClick={() => setMobileOpen(false)}
          />
          <div className="absolute inset-y-0 left-0 w-64 border-r border-border-subtle bg-surface-1">
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </div>
        </div>
      )}

      <div className="lg:pl-60">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border-subtle bg-surface-0/85 px-4 py-3 backdrop-blur lg:hidden">
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
            className="btn-ghost px-2 py-2"
          >
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" aria-hidden>
              <path
                d="M4 7h16M4 12h16M4 17h16"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
            </svg>
          </button>
          <Logo />
        </header>

        <main id="main-content" className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
