/**
 * Operational overview.
 *
 * Layout follows the reading order of a triage shift rather than the shape of
 * the data: what is happening now (activity), how bad (gauges), what kind
 * (distribution), and what specifically (recent). Every figure is aggregated
 * from the database per request — nothing here is hard-coded or cached.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ActivityChart, IndicatorTypeChart, RiskDistributionChart } from '../components/charts';
import { ArcGauge, Sparkbars, StatusGlyph, type StatusKind } from '../components/Gauges';
import { RiskBar } from '../components/RiskGauge';
import {
  Card,
  DemoBadge,
  EmptyState,
  ErrorState,
  IndicatorTypeBadge,
  LoadingState,
  VerdictBadge,
} from '../components/ui';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';
import { formatRelative, truncate } from '../lib/format';
import type { DashboardStats } from '../types/analysis';

/* -------------------------------------------------------------------------- */

/** Bottom stat row: glyph, label, big figure, and the total it is drawn from. */
function StatBlock({
  kind,
  value,
  total,
  caption,
}: {
  kind: StatusKind;
  value: number;
  total: number;
  caption: string;
}) {
  const labels: Record<StatusKind, string> = {
    protected: 'Protected',
    danger: 'Danger',
    alert: 'Alerts',
    unknown: 'Unknown',
  };

  return (
    <div>
      <div className="flex items-center gap-2.5">
        <StatusGlyph kind={kind} />
        <span className="text-sm font-medium text-content-primary">{labels[kind]}</span>
      </div>
      <p className="mt-5 text-xs text-content-muted">{caption}</p>
      <p className="mt-1 flex items-baseline gap-1.5">
        <span className="text-3xl font-semibold tabular-nums text-content-primary">{value}</span>
        <span className="text-sm text-content-muted tabular-nums">/ {total}</span>
      </p>
    </div>
  );
}

function RecentAnalyses({ stats }: { stats: DashboardStats }) {
  if (!stats.recent.length) {
    return (
      <EmptyState
        title="No analyses yet"
        message="Submit an indicator to see it appear here, or run the seed script to populate the dashboard with synthetic demo data."
        action={{ label: 'Analyze an indicator', to: '/analyze' }}
      />
    );
  }

  return (
    <ul className="divide-y divide-border-subtle">
      {stats.recent.map((item) => (
        <li key={item.id}>
          <Link
            to={`/analysis/${item.reference}`}
            className="flex items-center gap-4 rounded-xl px-2 py-3 transition-colors hover:bg-surface-2/70"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <p className="mono truncate text-content-primary">
                  {truncate(item.indicator_display, 48)}
                </p>
                {item.is_demo && <DemoBadge />}
              </div>
              <div className="mt-1.5 flex items-center gap-2 text-xs text-content-muted">
                <IndicatorTypeBadge type={item.indicator_type} />
                <span>{formatRelative(item.created_at)}</span>
              </div>
            </div>
            <div className="hidden sm:block">
              <RiskBar score={item.risk_score} verdict={item.verdict} />
            </div>
            <VerdictBadge verdict={item.verdict} />
          </Link>
        </li>
      ))}
    </ul>
  );
}

/* -------------------------------------------------------------------------- */

export default function Dashboard() {
  const [activityDays, setActivityDays] = useState(30);
  const { data, loading, error, refresh } = useFetch(
    () => api.dashboard(activityDays),
    [activityDays],
  );

  return (
    <>
      {/* Hero: oversized, low-weight heading with the primary action opposite. */}
      <header className="mb-8 flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-4xl leading-[1.05] font-light tracking-tight text-content-primary">
            System
            <br />
            <span className="font-semibold">Performance</span>
          </h1>
          <p className="mt-3 text-sm text-content-muted">
            {data ? `Live view across ${data.total_analyses} stored analyses` : 'Loading live view'}
          </p>
        </div>

        <Link to="/analyze" className="btn-primary shrink-0">
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" aria-hidden>
            <path
              d="M12 5v14M5 12h14"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
            />
          </svg>
          Analyze Indicator
        </Link>
      </header>

      {loading && <LoadingState label="Loading dashboard…" />}
      {error && <ErrorState message={error.message} onRetry={refresh} />}

      {data && (
        <div className="space-y-5">
          {/* Activity + gauges: the "what is happening" band. */}
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_260px]">
            <Card
              title="Analysis activity"
              description="Submissions per day, aggregated from stored analyses."
              actions={
                <div className="pill-group">
                  {[7, 30].map((days) => (
                    <button
                      key={days}
                      type="button"
                      onClick={() => setActivityDays(days)}
                      className={`pill ${
                        activityDays === days
                          ? 'bg-accent/15 text-accent'
                          : 'text-content-muted hover:text-content-primary'
                      }`}
                    >
                      {days}d
                    </button>
                  ))}
                </div>
              }
            >
              <div className="mb-5">
                <p className="label-text mb-2">Alert intensity</p>
                <Sparkbars values={data.activity.map((point) => point.count)} />
                <div className="mt-1 flex justify-between text-[11px] text-content-muted tabular-nums">
                  <span>{data.activity[0]?.date.slice(5)}</span>
                  <span>{data.activity[data.activity.length - 1]?.date.slice(5)}</span>
                </div>
              </div>
              <ActivityChart activity={data.activity} />
            </Card>

            <div className="card flex flex-col items-center justify-center gap-8 p-6">
              <ArcGauge
                value={data.malicious_count}
                max={Math.max(data.total_analyses, 1)}
                label="Malicious indicators"
                display={String(data.malicious_count)}
                color="var(--color-verdict-critical)"
              />
              <ArcGauge
                value={data.average_risk_score}
                max={100}
                label="Average risk score"
                display={String(Math.round(data.average_risk_score))}
                color="var(--color-accent)"
              />
            </div>
          </div>

          {/* Distribution: the "what kind" band. */}
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Card title="Threat severity distribution" description="Verdicts across all analyses.">
              <RiskDistributionChart byVerdict={data.by_verdict} />
            </Card>
            <Card title="Indicator types" description="What has been submitted to this instance.">
              <IndicatorTypeChart byType={data.by_indicator_type} />
            </Card>
          </div>

          {/* Totals: the headline counters, partitioning every stored analysis. */}
          <Card
            title="Total analyses by verdict"
            description="Every stored analysis falls into exactly one of these."
          >
            <div className="grid grid-cols-2 gap-8 lg:grid-cols-4">
              <StatBlock
                kind="protected"
                value={data.clean_count}
                total={data.total_analyses}
                caption="Clean and low risk"
              />
              <StatBlock
                kind="danger"
                value={data.malicious_count}
                total={data.total_analyses}
                caption="High risk and critical"
              />
              <StatBlock
                kind="alert"
                value={data.suspicious_count}
                total={data.total_analyses}
                caption="Warrant manual review"
              />
              <StatBlock
                kind="unknown"
                value={data.by_indicator_type.hash ?? 0}
                total={data.total_analyses}
                caption="Hash submissions"
              />
            </div>
          </Card>

          <Card
            title="Recent analyses"
            actions={
              <Link to="/history" className="text-xs font-medium text-accent hover:underline">
                View all
              </Link>
            }
          >
            <RecentAnalyses stats={data} />
          </Card>
        </div>
      )}
    </>
  );
}
