/**
 * Analysis history: search, filter, sort and paginate stored reports.
 *
 * Filter state lives in the URL query string rather than component state, so a
 * filtered view can be bookmarked, shared and survives a refresh -- which is
 * what an analyst hands to a colleague.
 */

import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RiskBar } from '../components/RiskGauge';
import {
  Card,
  DemoBadge,
  EmptyState,
  ErrorState,
  IndicatorTypeBadge,
  LoadingState,
  PageHeader,
  StatusBadge,
  VerdictBadge,
} from '../components/ui';
import { useFetch } from '../hooks/useAsync';
import { api } from '../services/api';
import {
  INDICATOR_LABEL,
  VERDICT_LABEL,
  VERDICT_ORDER,
  formatDateTime,
  truncate,
} from '../lib/format';
import type { IndicatorType, Verdict } from '../types/analysis';

const PAGE_SIZE = 15;

const COLUMNS: { key: string; label: string; sortable: boolean; className?: string }[] = [
  { key: 'created_at', label: 'Date', sortable: true, className: 'w-44' },
  { key: 'indicator', label: 'Indicator', sortable: true },
  { key: 'indicator_type', label: 'Type', sortable: true, className: 'w-28' },
  { key: 'risk_score', label: 'Risk score', sortable: true, className: 'w-36' },
  { key: 'verdict', label: 'Verdict', sortable: true, className: 'w-32' },
  { key: 'status', label: 'Status', sortable: false, className: 'w-24' },
];

export default function History() {
  const [params, setParams] = useSearchParams();

  const page = Number(params.get('page') ?? 1);
  const search = params.get('search') ?? '';
  const indicatorType = (params.get('indicator_type') ?? '') as IndicatorType | '';
  const verdict = (params.get('verdict') ?? '') as Verdict | '';
  const sortBy = params.get('sort_by') ?? 'created_at';
  const sortDir = (params.get('sort_dir') ?? 'desc') as 'asc' | 'desc';

  // Local mirror of the search box so typing stays responsive; the URL (and
  // therefore the request) only updates after the user pauses.
  const [searchDraft, setSearchDraft] = useState(search);
  useEffect(() => setSearchDraft(search), [search]);

  useEffect(() => {
    if (searchDraft === search) return;
    const timer = setTimeout(() => update({ search: searchDraft, page: '1' }), 300);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft]);

  function update(changes: Record<string, string>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    setParams(next, { replace: true });
  }

  const { data, loading, error, refresh } = useFetch(
    () =>
      api.listAnalyses({
        page,
        page_size: PAGE_SIZE,
        search: search || undefined,
        indicator_type: indicatorType || undefined,
        verdict: verdict || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
      }),
    [page, search, indicatorType, verdict, sortBy, sortDir],
  );

  function toggleSort(key: string) {
    const nextDir = sortBy === key && sortDir === 'desc' ? 'asc' : 'desc';
    update({ sort_by: key, sort_dir: nextDir, page: '1' });
  }

  const hasFilters = Boolean(search || indicatorType || verdict);

  return (
    <>
      <PageHeader
        title="Analysis history"
        subtitle="Every analysis stored by this instance. Select a row to open its full report."
        actions={
          <Link to="/analyze" className="btn-primary">
            Analyze Indicator
          </Link>
        }
      />

      <Card className="mb-5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="sm:col-span-2">
            <label htmlFor="search" className="label-text mb-1.5 block">
              Search
            </label>
            <input
              id="search"
              type="search"
              value={searchDraft}
              onChange={(event) => setSearchDraft(event.target.value)}
              placeholder="Indicator or SC- reference"
              className="input-field"
            />
          </div>

          <div>
            <label htmlFor="type-filter" className="label-text mb-1.5 block">
              Indicator type
            </label>
            <select
              id="type-filter"
              value={indicatorType}
              onChange={(event) => update({ indicator_type: event.target.value, page: '1' })}
              className="input-field"
            >
              <option value="">All types</option>
              {(Object.keys(INDICATOR_LABEL) as IndicatorType[]).map((type) => (
                <option key={type} value={type}>
                  {INDICATOR_LABEL[type]}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="verdict-filter" className="label-text mb-1.5 block">
              Verdict
            </label>
            <select
              id="verdict-filter"
              value={verdict}
              onChange={(event) => update({ verdict: event.target.value, page: '1' })}
              className="input-field"
            >
              <option value="">All verdicts</option>
              {VERDICT_ORDER.map((value) => (
                <option key={value} value={value}>
                  {VERDICT_LABEL[value]}
                </option>
              ))}
            </select>
          </div>
        </div>

        {hasFilters && (
          <button
            type="button"
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
            className="mt-3 text-xs font-medium text-accent hover:underline"
          >
            Clear all filters
          </button>
        )}
      </Card>

      <div className="card overflow-hidden">
        {loading && <LoadingState label="Loading analyses…" />}
        {error && <ErrorState message={error.message} onRetry={refresh} />}

        {data && !loading && !error && (
          <>
            {data.items.length === 0 ? (
              <EmptyState
                title={hasFilters ? 'No matching analyses' : 'No analyses yet'}
                message={
                  hasFilters
                    ? 'No stored analysis matches these filters. Try widening the search.'
                    : 'Submit an indicator to build up a history, or run the seed script for synthetic demo data.'
                }
                action={hasFilters ? undefined : { label: 'Analyze an indicator', to: '/analyze' }}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[820px] text-sm">
                  <thead>
                    <tr className="border-b border-border-subtle text-left">
                      {COLUMNS.map((column) => (
                        <th
                          key={column.key}
                          scope="col"
                          className={`px-5 py-3 ${column.className ?? ''}`}
                          aria-sort={
                            sortBy === column.key
                              ? sortDir === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : undefined
                          }
                        >
                          {column.sortable ? (
                            <button
                              type="button"
                              onClick={() => toggleSort(column.key)}
                              className="label-text flex items-center gap-1 hover:text-content-primary"
                            >
                              {column.label}
                              <span aria-hidden className="text-[9px]">
                                {sortBy === column.key ? (sortDir === 'asc' ? '▲' : '▼') : '⇅'}
                              </span>
                            </button>
                          ) : (
                            <span className="label-text">{column.label}</span>
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle">
                    {data.items.map((item) => (
                      <tr key={item.id} className="transition-colors hover:bg-surface-2/50">
                        <td className="px-5 py-3.5 whitespace-nowrap text-content-secondary">
                          {formatDateTime(item.created_at)}
                        </td>
                        <td className="max-w-xs px-5 py-3.5">
                          <div className="flex items-center gap-2">
                            <Link
                              to={`/analysis/${item.reference}`}
                              className="mono truncate text-content-primary hover:text-accent hover:underline"
                              title={item.indicator_display}
                            >
                              {truncate(item.indicator_display, 46)}
                            </Link>
                            {item.is_demo && <DemoBadge />}
                          </div>
                          <p className="mt-0.5 font-mono text-[11px] text-content-muted">
                            {item.reference}
                          </p>
                        </td>
                        <td className="px-5 py-3.5">
                          <IndicatorTypeBadge type={item.indicator_type} />
                        </td>
                        <td className="px-5 py-3.5">
                          <RiskBar score={item.risk_score} verdict={item.verdict} />
                        </td>
                        <td className="px-5 py-3.5">
                          <VerdictBadge verdict={item.verdict} />
                        </td>
                        <td className="px-5 py-3.5">
                          <StatusBadge status={item.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {data.total > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle px-5 py-3.5 text-sm">
                <p className="text-content-muted">
                  Showing{' '}
                  <span className="text-content-primary">
                    {(data.page - 1) * data.page_size + 1}–
                    {Math.min(data.page * data.page_size, data.total)}
                  </span>{' '}
                  of <span className="text-content-primary">{data.total}</span>
                </p>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="btn-secondary px-3 py-1.5 text-xs"
                    disabled={data.page <= 1}
                    onClick={() => update({ page: String(data.page - 1) })}
                  >
                    Previous
                  </button>
                  <span className="px-1 text-xs text-content-muted">
                    Page {data.page} of {data.total_pages}
                  </span>
                  <button
                    type="button"
                    className="btn-secondary px-3 py-1.5 text-xs"
                    disabled={data.page >= data.total_pages}
                    onClick={() => update({ page: String(data.page + 1) })}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
