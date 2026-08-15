/** Presentation helpers shared across pages. */

import type { IndicatorType, Severity, Verdict } from '../types/analysis';

export const VERDICT_LABEL: Record<Verdict, string> = {
  clean: 'Clean',
  low_risk: 'Low Risk',
  suspicious: 'Suspicious',
  high_risk: 'High Risk',
  critical: 'Critical',
};

/**
 * Verdict colours as raw values rather than Tailwind classes, because Recharts
 * takes fills as strings and the two must not drift apart.
 */
export const VERDICT_COLOR: Record<Verdict, string> = {
  clean: '#2ee6a6',
  low_risk: '#9be36a',
  suspicious: '#f5a524',
  high_risk: '#fb7a6d',
  critical: '#f4475f',
};

export const VERDICT_ORDER: Verdict[] = [
  'clean',
  'low_risk',
  'suspicious',
  'high_risk',
  'critical',
];

export const INDICATOR_LABEL: Record<IndicatorType, string> = {
  url: 'URL',
  domain: 'Domain',
  ip: 'IP Address',
  hash: 'File Hash',
  file: 'File',
};

export const INDICATOR_PLURAL: Record<IndicatorType, string> = {
  url: 'URLs',
  domain: 'Domains',
  ip: 'IPs',
  hash: 'Hashes',
  file: 'Files',
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
  pass: 4,
};

export function verdictFor(score: number): Verdict {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high_risk';
  if (score >= 50) return 'suspicious';
  if (score >= 20) return 'low_risk';
  return 'clean';
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDateShort(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDateShort(iso);
}

export function formatDuration(seconds: number): string {
  if (seconds < 0.001) return '<1 ms';
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  return `${seconds.toFixed(2)} s`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 bytes';
  const units = ['bytes', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, index);
  return `${index === 0 ? value : value.toFixed(1)} ${units[index]}`;
}

export function truncate(value: string, max = 64): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

/** Turns a details key such as `registrable_domain` into "Registrable domain". */
export function humanizeKey(key: string): string {
  const spaced = key.replace(/_/g, ' ').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function formatDetailValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
