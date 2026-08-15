/**
 * Dashboard charts.
 *
 * Every series is fed from `/api/stats/dashboard`, which aggregates live rows.
 * Nothing here carries fallback or placeholder numbers: an empty database
 * renders an explicit empty state rather than an invented shape.
 */

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { ActivityPoint, IndicatorType, Verdict } from '../types/analysis';
import {
  INDICATOR_PLURAL,
  VERDICT_COLOR,
  VERDICT_LABEL,
  VERDICT_ORDER,
  formatDateShort,
} from '../lib/format';

const AXIS_COLOR = '#638077';
const GRID_COLOR = '#1a2724';

const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: '#121a18',
    border: '1px solid #273a35',
    borderRadius: '12px',
    fontSize: '12px',
    color: '#e4f0ec',
  },
  labelStyle: { color: '#93aaa3', marginBottom: 4 },
  cursor: { fill: '#ffffff08' },
} as const;

function ChartEmpty({ message }: { message: string }) {
  return (
    <div className="flex h-[240px] items-center justify-center text-center text-xs text-content-muted">
      {message}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function RiskDistributionChart({ byVerdict }: { byVerdict: Record<Verdict, number> }) {
  const data = VERDICT_ORDER.map((verdict) => ({
    name: VERDICT_LABEL[verdict],
    value: byVerdict[verdict] ?? 0,
    color: VERDICT_COLOR[verdict],
  })).filter((entry) => entry.value > 0);

  if (!data.length)
    return <ChartEmpty message="No analyses yet — run one to populate this chart." />;

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius={52}
          outerRadius={82}
          paddingAngle={2}
          stroke="#0c1211"
          strokeWidth={2}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip {...TOOLTIP_STYLE} />
        <Legend
          verticalAlign="bottom"
          height={36}
          iconType="circle"
          iconSize={8}
          formatter={(value) => <span style={{ color: '#93aaa3', fontSize: 12 }}>{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

/* -------------------------------------------------------------------------- */

export function ActivityChart({ activity }: { activity: ActivityPoint[] }) {
  const hasData = activity.some((point) => point.count > 0);
  if (!hasData) return <ChartEmpty message="No activity recorded in this period." />;

  const data = activity.map((point) => ({ ...point, label: formatDateShort(point.date) }));

  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id="fill-total" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2ee6a6" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#2ee6a6" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="fill-malicious" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f4475f" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#f4475f" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID_COLOR} strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: AXIS_COLOR, fontSize: 11 }}
          axisLine={{ stroke: GRID_COLOR }}
          tickLine={false}
          // Thin the labels so a 30-day series stays readable on narrow screens.
          interval={Math.max(0, Math.floor(data.length / 8) - 1)}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fill: AXIS_COLOR, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={38}
        />
        <Tooltip {...TOOLTIP_STYLE} />
        <Legend
          verticalAlign="top"
          height={28}
          iconType="circle"
          iconSize={8}
          formatter={(value) => <span style={{ color: '#93aaa3', fontSize: 12 }}>{value}</span>}
        />
        <Area
          type="monotone"
          dataKey="count"
          name="All analyses"
          stroke="#2ee6a6"
          strokeWidth={2}
          fill="url(#fill-total)"
        />
        <Area
          type="monotone"
          dataKey="malicious"
          name="High risk & critical"
          stroke="#f4475f"
          strokeWidth={2}
          fill="url(#fill-malicious)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/* -------------------------------------------------------------------------- */

export function IndicatorTypeChart({ byType }: { byType: Record<IndicatorType, number> }) {
  const data = (Object.keys(INDICATOR_PLURAL) as IndicatorType[])
    .map((type) => ({ name: INDICATOR_PLURAL[type], value: byType[type] ?? 0 }))
    .filter((entry) => entry.value > 0);

  if (!data.length)
    return <ChartEmpty message="No analyses yet — run one to populate this chart." />;

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
        <CartesianGrid stroke={GRID_COLOR} strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fill: AXIS_COLOR, fontSize: 11 }}
          axisLine={{ stroke: GRID_COLOR }}
          tickLine={false}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fill: AXIS_COLOR, fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={38}
        />
        <Tooltip {...TOOLTIP_STYLE} />
        <Bar dataKey="value" name="Analyses" fill="#2ee6a6" radius={[4, 4, 0, 0]} maxBarSize={54} />
      </BarChart>
    </ResponsiveContainer>
  );
}
