/**
 * Arc gauges and status glyphs.
 *
 * The gauge is a three-quarter arc rather than a full ring: the gap at the
 * bottom gives the value a baseline to sit against, so a low reading looks
 * low instead of looking like a ring with a piece missing.
 *
 * Glyphs matter as much as colour here. Protected/danger/alert/unknown each
 * get a distinct *shape* — shield, triangle, circle, square — so the four
 * states stay distinguishable in greyscale and to colour-blind readers, which
 * a colour-only legend would not.
 */

import type { ReactNode } from 'react';
import type { Verdict } from '../types/analysis';
import { VERDICT_COLOR, VERDICT_LABEL } from '../lib/format';

/* -------------------------------------------------------------------------- */
/* Status glyphs                                                              */
/* -------------------------------------------------------------------------- */

export type StatusKind = 'protected' | 'danger' | 'alert' | 'unknown';

const STATUS_COLOR: Record<StatusKind, string> = {
  protected: 'var(--color-verdict-clean)',
  danger: 'var(--color-verdict-critical)',
  alert: 'var(--color-verdict-suspicious)',
  unknown: 'var(--color-content-muted)',
};

/** Distinct silhouette per state — the shape carries the meaning, not the hue. */
export function StatusGlyph({ kind, size = 26 }: { kind: StatusKind; size?: number }) {
  const color = STATUS_COLOR[kind];
  const shapes: Record<StatusKind, ReactNode> = {
    protected: <path d="M12 3 5 6v6c0 4.4 3 8.4 7 9.5 4-1.1 7-5.1 7-9.5V6l-7-3Z" />,
    danger: <path d="M12 3.5 22 20H2L12 3.5Z" />,
    alert: <circle cx="12" cy="12" r="9.5" />,
    unknown: <rect x="3.5" y="3.5" width="17" height="17" rx="3.5" />,
  };

  return (
    <span
      className="inline-flex shrink-0 items-center justify-center rounded-full"
      style={{
        width: size,
        height: size,
        backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)`,
      }}
      aria-hidden
    >
      <svg viewBox="0 0 24 24" width={size * 0.58} height={size * 0.58} fill={color}>
        {shapes[kind]}
      </svg>
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Arc gauge                                                                  */
/* -------------------------------------------------------------------------- */

const ARC_SWEEP = 0.72; // three-quarter arc, open at the bottom

export function ArcGauge({
  value,
  max,
  label,
  display,
  color = 'var(--color-accent)',
  size = 132,
}: {
  value: number;
  max: number;
  label: string;
  display: string;
  color?: string;
  size?: number;
}) {
  const stroke = size / 13;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const track = circumference * ARC_SWEEP;
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          // Rotated so the arc's gap sits centred at the bottom.
          style={{ transform: `rotate(${90 + (1 - ARC_SWEEP) * 180}deg)` }}
          role="img"
          aria-label={`${label}: ${display}`}
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--color-surface-3)"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${track} ${circumference - track}`}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${track * ratio} ${circumference - track * ratio}`}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-semibold tabular-nums"
            style={{ fontSize: size / 4.6, lineHeight: 1, color }}
          >
            {display}
          </span>
        </div>
      </div>
      <p className="mt-2 text-center text-xs text-content-secondary">{label}</p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Risk gauge (report header)                                                 */
/* -------------------------------------------------------------------------- */

export function RiskArc({
  score,
  verdict,
  size = 172,
}: {
  score: number;
  verdict: Verdict;
  size?: number;
}) {
  const clamped = Math.max(0, Math.min(100, score));
  const color = VERDICT_COLOR[verdict];
  const stroke = size / 13;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const track = circumference * ARC_SWEEP;

  return (
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Risk score ${clamped} of 100. Verdict: ${VERDICT_LABEL[verdict]}.`}
    >
      <svg
        width={size}
        height={size}
        style={{ transform: `rotate(${90 + (1 - ARC_SWEEP) * 180}deg)` }}
        aria-hidden
      >
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--color-surface-3)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${track} ${circumference - track}`}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${track * (clamped / 100)} ${circumference - track * (clamped / 100)}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-semibold tabular-nums"
          style={{ color, fontSize: size / 3.8, lineHeight: 1 }}
        >
          {clamped}
        </span>
        <span className="mt-1 text-[11px] tracking-[0.14em] text-content-muted uppercase">
          / 100
        </span>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Sparkline                                                                  */
/* -------------------------------------------------------------------------- */

/** Dense bar strip — the "intensity" readout from the reference layout. */
export function Sparkbars({
  values,
  color = 'var(--color-accent)',
  height = 44,
}: {
  values: number[];
  color?: string;
  height?: number;
}) {
  if (!values.length) {
    return (
      <div style={{ height }} className="flex items-center text-xs text-content-muted">
        No data
      </div>
    );
  }
  const peak = Math.max(...values, 1);

  return (
    <div className="flex items-end gap-[2px]" style={{ height }} aria-hidden>
      {values.map((value, index) => (
        <div
          key={index}
          className="flex-1 rounded-[1px]"
          style={{
            height: `${Math.max(6, (value / peak) * 100)}%`,
            backgroundColor: value > 0 ? color : 'var(--color-surface-3)',
            opacity: value > 0 ? 0.45 + (value / peak) * 0.55 : 1,
          }}
        />
      ))}
    </div>
  );
}
