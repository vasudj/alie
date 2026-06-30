'use client';

import React, { useMemo } from 'react';
import { useAppSelector } from '../redux/hooks';
import { generateTrafficChartData } from '../services/api';
import { ScanHistoryEntry } from '../types';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  createColumnHelper,
  getSortedRowModel,
  SortingState,
} from '@tanstack/react-table';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Calendar, Shield } from 'lucide-react';

// ─── 270° Arc Gauge Helpers ─────────────────────────────────────────────────

const ARC_RADIUS = 70;
const ARC_CENTER = 90;
const ARC_STROKE = 8;
const ARC_ANGLE = (270 * Math.PI) / 180;

function describeArc(
  cx: number,
  cy: number,
  r: number,
  startAngle: number,
  endAngle: number,
): string {
  const start = {
    x: cx + r * Math.cos(startAngle),
    y: cy + r * Math.sin(startAngle),
  };
  const end = {
    x: cx + r * Math.cos(endAngle),
    y: cy + r * Math.sin(endAngle),
  };
  const largeArc = endAngle - startAngle > Math.PI ? 1 : 0;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`;
}

const ARC_START_ANGLE = (135 * Math.PI) / 180;
const ARC_END_ANGLE = ARC_START_ANGLE + ARC_ANGLE;
const trackPath = describeArc(ARC_CENTER, ARC_CENTER, ARC_RADIUS, ARC_START_ANGLE, ARC_END_ANGLE);

// ─── Scan History Column Helper ─────────────────────────────────────────────

const scanColumnHelper = createColumnHelper<ScanHistoryEntry>();

// ─── Component ──────────────────────────────────────────────────────────────

export default function CommandCenter() {
  const metrics = useAppSelector((state) => state.system.metrics);
  const scanHistory = useAppSelector((state) => state.system.scanHistory);
  const events = useAppSelector((state) => state.telemetry.events);

  const [sorting, setSorting] = React.useState<SortingState>([]);

  // ─── Chart Data ────────────────────────────────────────────────────
  const chartData = useMemo(
    () => generateTrafficChartData(events.length, metrics.threats_neutralized ?? 0),
    [events.length, metrics.threats_neutralized],
  );

  // ─── Risk Gauge Arc ────────────────────────────────────────────────
  const fillRatio = Math.min((metrics.risk_score ?? 0) / 100, 1);
  const filledAngle = ARC_START_ANGLE + ARC_ANGLE * fillRatio;
  const activePath =
    fillRatio > 0
      ? describeArc(ARC_CENTER, ARC_CENTER, ARC_RADIUS, ARC_START_ANGLE, filledAngle)
      : '';

  const riskScore = metrics.risk_score ?? 0;
  const severityLabel = riskScore > 70 ? 'High' : riskScore > 50 ? 'Medium' : 'Low';
  const severityDot =
    riskScore > 70
      ? 'bg-rose-400'
      : riskScore > 50
        ? 'bg-amber-400'
        : 'bg-emerald-400';

  // ─── KPI Card Data ────────────────────────────────────────────────
  const kpiCards = [
    { label: 'Shadow API Detection', value: `${metrics.shadow_api_percent ?? 0}%`, status: 'Optimal' },
    { label: 'Incident Discovery',   value: metrics.incident_discovery_time ?? '—',   status: 'Real-time' },
    { label: 'Added Latency',        value: metrics.added_latency ?? '—',              status: '<1ms target' },
    { label: 'Threats Neutralized',  value: (metrics.threats_neutralized ?? 0).toLocaleString(), status: 'Streaming' },
  ];

  // ─── Scan History Columns ─────────────────────────────────────────
  const scanColumns = useMemo(
    () => [
      scanColumnHelper.accessor('created_at', {
        header: 'Timestamp',
        cell: (info) => (
          <span className="font-mono text-[11px] text-on-surface-variant">{info.getValue()}</span>
        ),
      }),
      scanColumnHelper.accessor('scan_target', {
        header: 'Scan Target',
        cell: (info) => (
          <span className="text-sm text-on-surface">{info.getValue()}</span>
        ),
      }),
      scanColumnHelper.accessor('total_apis_scanned', {
        header: 'Total APIs Scanned',
        cell: (info) => (
          <span className="font-mono text-[11px] text-on-surface">
            {info.getValue().toLocaleString()}
          </span>
        ),
      }),
      scanColumnHelper.accessor('vulnerabilities_found', {
        header: 'Vulnerabilities Found',
        cell: (info) => (
          <span className="font-mono text-[11px] text-on-surface">{info.getValue()}</span>
        ),
      }),
      scanColumnHelper.accessor('engine_status', {
        header: 'Engine Status',
        cell: (info) => {
          const status = info.getValue();
          const dotColor =
            status === 'Completed'
              ? 'bg-emerald-400'
              : status === 'Running'
                ? 'bg-amber-400'
                : 'bg-rose-400';
          return (
            <span className="flex items-center gap-1.5 text-xs text-on-surface-variant">
              <span className={`w-1.5 h-1.5 rounded-full ${dotColor} shrink-0`} />
              {status}
            </span>
          );
        },
      }),
    ],
    [],
  );

  const scanTable = useReactTable({
    data: scanHistory,
    columns: scanColumns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  // ─── Render ────────────────────────────────────────────────────────

  return (
    <div className="p-5 space-y-grid-unit">
      {/* ── 1. Filter Toolbar ────────────────────────────────────────── */}
      <div className="flex justify-between items-center bg-bg-surface border border-border-grid rounded-lg p-3">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-on-surface-variant" />
          <span className="text-sm font-medium text-on-surface-variant">Filter Range</span>
          <input
            type="date"
            defaultValue="2026-05-29"
            className="bg-bg-canvas border border-border-grid rounded-md text-on-surface px-3 py-1.5 text-xs font-mono outline-none focus:border-primary"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs text-on-surface-variant">Live</span>
        </div>
      </div>

      {/* ── 2. Risk Gauge + Traffic Chart ─────────────────────────────── */}
      <div className="grid grid-cols-12 gap-grid-unit">
        {/* Risk Gauge Card (4 cols) */}
        <section className="col-span-12 lg:col-span-4 bg-bg-surface border border-border-grid rounded-lg flex flex-col min-h-[300px]">
          <div className="p-4 flex justify-between items-center border-b border-border-grid">
            <span className="text-sm font-semibold text-on-surface">Risk Score</span>
            <Shield className="w-4 h-4 text-on-surface-variant" />
          </div>

          <div className="flex-grow flex flex-col items-center justify-center py-6">
            <div className="relative w-[180px] h-[180px] flex items-center justify-center">
              <svg viewBox="0 0 180 180" className="w-full h-full">
                <path
                  d={trackPath}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={ARC_STROKE}
                  strokeLinecap="round"
                  className="text-border-grid"
                />
                {activePath && (
                  <path
                    d={activePath}
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={ARC_STROKE}
                    strokeLinecap="round"
                    className="text-primary transition-all duration-1000 ease-out"
                  />
                )}
              </svg>
              <div className="absolute flex flex-col items-center text-center">
                <span className="font-mono text-4xl font-bold text-on-surface tracking-tighter">
                  {riskScore}
                </span>
                <span className="flex items-center gap-1.5 text-xs text-on-surface-variant mt-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${severityDot}`} />
                  {severityLabel}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* Traffic Flow Chart (8 cols) */}
        <section className="col-span-12 lg:col-span-8 bg-bg-surface border border-border-grid rounded-lg flex flex-col min-h-[300px]">
          <div className="p-4 flex justify-between items-center border-b border-border-grid">
            <span className="text-sm font-semibold text-on-surface">Traffic Analytics</span>
            <div className="flex gap-4">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-[3px] bg-[#34D399]" />
                <span className="text-[10px] text-on-surface-variant">Traffic RPM</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-[3px] bg-[#F43F5E]" />
                <span className="text-[10px] text-on-surface-variant">Threats</span>
              </div>
            </div>
          </div>

          <div className="flex-grow p-4 relative flex items-center justify-center">
            <div className="w-full h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradTraffic" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34D399" stopOpacity={0.05} />
                      <stop offset="95%" stopColor="#34D399" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.08} />
                      <stop offset="95%" stopColor="#F43F5E" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgb(var(--border-grid))" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="time"
                    stroke="rgb(var(--on-surface-variant))"
                    fontSize={10}
                    fontFamily="monospace"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="rgb(var(--on-surface-variant))"
                    fontSize={10}
                    fontFamily="monospace"
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgb(var(--bg-surface))',
                      borderColor: 'rgb(var(--border-grid))',
                      color: 'rgb(var(--on-surface))',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                      borderRadius: '6px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="traffic"
                    name="Requests"
                    stroke="#34D399"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#gradTraffic)"
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    name="Threats"
                    stroke="#F43F5E"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#gradThreats)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      </div>

      {/* ── 3. KPI Cards ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-grid-unit">
        {kpiCards.map((card) => (
          <div
            key={card.label}
            className="bg-bg-surface border border-border-grid rounded-lg p-4 hover:border-on-surface-variant/30 transition-colors cursor-default"
          >
            <span className="text-xs font-medium text-on-surface-variant">{card.label}</span>
            <div className="flex items-baseline justify-between mt-3">
              <span className="font-mono text-2xl font-semibold text-on-surface">{card.value}</span>
              <span className="text-xs text-on-surface-variant">{card.status}</span>
            </div>
            <div className="w-full h-px bg-border-grid mt-3" />
          </div>
        ))}
      </div>

      {/* ── 4. Codebase Scan History ──────────────────────────────────── */}
      <section className="bg-bg-surface border border-border-grid rounded-lg overflow-hidden">
        <div className="p-4 border-b border-border-grid">
          <h2 className="text-sm font-semibold text-on-surface">Codebase Scan History</h2>
        </div>

        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full border-collapse">
            <thead className="bg-surface-container border-b border-border-grid">
              {scanTable.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getToggleSortingHandler()}
                      className="px-4 py-2.5 text-left text-xs font-medium text-on-surface-variant uppercase tracking-wider cursor-pointer select-none hover:text-on-surface transition-colors"
                    >
                      <div className="flex items-center gap-1">
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                        {{ asc: ' ▲', desc: ' ▼' }[header.column.getIsSorted() as string] ?? null}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-border-grid/30">
              {scanTable.getRowModel().rows.length > 0 ? (
                scanTable.getRowModel().rows.map((row, rowIndex) => (
                  <tr
                    key={row.id}
                    className={`hover:bg-surface-container/50 transition-colors ${
                      rowIndex % 2 === 1 ? 'bg-surface-container/30' : ''
                    }`}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-4 py-2.5 align-middle">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={scanColumns.length}
                    className="px-4 py-8 text-center text-sm text-on-surface-variant"
                  >
                    No scan history available
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
