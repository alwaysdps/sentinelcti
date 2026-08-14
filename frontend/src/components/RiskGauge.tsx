/**
 * Circular risk indicator used at the top of every report.
 *
 * Deliberately labelled "Risk Score" with the verdict spelled out underneath:
 * the number alone invites reading it as a probability of maliciousness, which
 * it is not.
 */

import type { Verdict } from '../types/analysis';
import { VERDICT_COLOR, VERDICT_LABEL } from '../lib/format';

export function RiskGauge({
  score,
  verdict,
  size = 168,
}: {
  score: number;
  verdict: Verdict;
  size?: number;
}) {
  const strokeWidth = size / 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const dash = (clamped / 100) * circumference;
  const color = VERDICT_COLOR[verdict];

  return (
    <div
      className="relative inline-flex shrink-0 items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Risk score ${clamped} out of 100. Verdict: ${VERDICT_LABEL[verdict]}.`}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1e2a41"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-semibold tabular-nums"
          style={{ color, fontSize: size / 3.6, lineHeight: 1 }}
        >
          {clamped}
        </span>
        <span className="mt-1 text-xs text-content-muted">/ 100</span>
      </div>
    </div>
  );
}

/** Horizontal variant for compact contexts such as table rows. */
export function RiskBar({ score, verdict }: { score: number; verdict: Verdict }) {
  const clamped = Math.max(0, Math.min(100, score));
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-3"
        role="img"
        aria-label={`Risk score ${clamped} of 100`}
      >
        <div
          className="h-full rounded-full"
          style={{ width: `${clamped}%`, backgroundColor: VERDICT_COLOR[verdict] }}
        />
      </div>
      <span className="w-7 text-right text-sm font-medium tabular-nums text-content-primary">
        {clamped}
      </span>
    </div>
  );
}
