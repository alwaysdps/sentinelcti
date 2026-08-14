/** Submission workspace: a tab strip over the five indicator types. */

import { NavLink, Outlet } from 'react-router-dom';
import { InlineNotice, PageHeader } from '../components/ui';

const TABS = [
  { to: '/analyze/url', label: 'URL' },
  { to: '/analyze/file', label: 'File' },
  { to: '/analyze/hash', label: 'Hash' },
  { to: '/analyze/ip', label: 'IP Address' },
  { to: '/analyze/domain', label: 'Domain' },
];

export default function Analyze() {
  return (
    <>
      <PageHeader
        title="Analyze Indicator"
        subtitle="Submit a suspicious indicator for static, non-invasive analysis. Every submission produces an explainable risk score and a stored report."
      />

      <div className="mb-5">
        <InlineNotice>
          <strong className="text-content-primary">Defensive analysis only.</strong> Uploaded files
          are never executed, extracted or parsed by a format handler; submitted URLs are never
          fetched; submitted IP addresses are never contacted. Analysis is limited to hashing,
          content inspection and pattern matching.
        </InlineNotice>
      </div>

      <div
        className="mb-6 flex gap-1 overflow-x-auto border-b border-border-subtle"
        role="tablist"
        aria-label="Indicator type"
      >
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            role="tab"
            className={({ isActive }) =>
              `-mb-px shrink-0 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'border-accent text-accent'
                  : 'border-transparent text-content-secondary hover:border-border-strong hover:text-content-primary'
              }`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </div>

      <Outlet />
    </>
  );
}
