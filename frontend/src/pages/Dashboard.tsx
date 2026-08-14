/** Operational overview. Every figure comes from the live database. */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ActivityChart, IndicatorTypeChart, RiskDistributionChart } from '../components/charts';
import { RiskBar } from '../components/RiskGauge';
import {
  Card,
  DemoBadge,
  EmptyState,
  ErrorState,
  IndicatorTypeBadge,
  LoadingState,
  PageHeader,
  VerdictBadge,
} from '../components/ui';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';
import { formatRelative, truncate } from '../lib/format';
import type { DashboardStats } from '../types/analysis';

function StatCard({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: number | string;
  hint: string;
  accent: string;
}) {
  return (
    <div className="card-padded">
      <div className="flex items-start justify-between gap-3">
        <p className="label-text">{label}</p>
        <span
          className="h-2 w-2 shrink-0 rounded-full"
          style={{ backgroundColor: accent }}
          aria-hidden
        />
      </div>
      <p className="mt-3 text-3xl font-semibold tabular-nums text-content-primary">{value}</p>
      <p className="mt-1.5 text-xs text-content-muted">{hint}</p>
    </div>
  );
}

function RecentAnalyses({ stats }: { stats: DashboardStats }) {
  if (!stats.recent.length) {
    return (
      <EmptyState
        title="No analyses yet"
        message="Submit an indicator to see it appear here. Run the seed script to populate the dashboard with synthetic demo data."
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
            className="flex items-center gap-4 px-1 py-3 transition-colors hover:bg-surface-2/60"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <p className="mono truncate text-content-primary">
                  {truncate(item.indicator_display, 52)}
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

export default function Dashboard() {
  const [activityDays, setActivityDays] = useState(30);
  const { data, loading, error, refresh } = useFetch(
    () => api.dashboard(activityDays),
    [activityDays],
  );

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="Live overview of every indicator analysed by this instance."
        actions={
          <Link to="/analyze" className="btn-primary">
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" aria-hidden>
              <path
                d="M12 5v14M5 12h14"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
            Analyze Indicator
          </Link>
        }
      />

      {loading && <LoadingState label="Loading dashboard…" />}
      {error && <ErrorState message={error.message} onRetry={refresh} />}

      {data && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Total analyses"
              value={data.total_analyses}
              hint={`Average risk score ${data.average_risk_score}`}
              accent="#38bdf8"
            />
            <StatCard
              label="Malicious"
              value={data.malicious_count}
              hint="High risk and critical verdicts"
              accent="#f43f5e"
            />
            <StatCard
              label="Suspicious"
              value={data.suspicious_count}
              hint="Warrant manual review"
              accent="#fbbf24"
            />
            <StatCard
              label="Clean"
              value={data.clean_count}
              hint="Clean and low-risk verdicts"
              accent="#34d399"
            />
          </div>

          <Card
            title="Analysis activity"
            description="Submissions per day, aggregated from stored analyses."
            actions={
              <div className="flex gap-1 rounded-lg border border-border-subtle bg-surface-2 p-0.5">
                {[7, 30].map((days) => (
                  <button
                    key={days}
                    type="button"
                    onClick={() => setActivityDays(days)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
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
            <ActivityChart activity={data.activity} />
          </Card>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Card title="Threat severity distribution" description="Verdicts across all analyses.">
              <RiskDistributionChart byVerdict={data.by_verdict} />
            </Card>
            <Card title="Indicator types" description="What has been submitted to this instance.">
              <IndicatorTypeChart byType={data.by_indicator_type} />
            </Card>
          </div>

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
