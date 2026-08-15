/**
 * Brand marks.
 *
 * The shield lives here rather than being redrawn per page: it appears in the
 * sidebar, on the landing page and on the login screen, and three copies of the
 * same path data would drift the first time the mark is adjusted.
 */

export function ShieldMark({ className = 'h-7 w-7' }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={`text-accent ${className}`} aria-hidden>
      <path
        fill="currentColor"
        d="M16 2 4 7v9c0 7.2 5.1 13.9 12 15.5C22.9 29.9 28 23.2 28 16V7L16 2Zm0 3.3 9 3.7v7c0 5.7-3.8 11-9 12.5C10.8 27 7 21.7 7 16V9l9-3.7Z"
      />
      <path fill="currentColor" d="M14.6 19.4 11 15.8l1.8-1.8 1.8 1.8 4.6-4.6 1.8 1.8-6.4 6.4Z" />
    </svg>
  );
}

/** Horizontal lockup: mark, name, and the category line beneath it. */
export function Logo({ subtitle = 'Threat Intel' }: { subtitle?: string }) {
  return (
    <div className="flex items-center gap-2.5">
      <ShieldMark />
      <div className="leading-tight">
        <p className="text-sm font-semibold tracking-tight text-content-primary">SentinelCTI</p>
        <p className="text-[10px] tracking-[0.18em] text-content-muted uppercase">{subtitle}</p>
      </div>
    </div>
  );
}
