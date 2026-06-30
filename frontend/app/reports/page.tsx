'use client';

import React, { useMemo } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { setComplianceFilter, setSearchTerm } from '../../redux/assetSlice';
import { AssetRoute } from '../../types';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  createColumnHelper,
  getSortedRowModel,
  SortingState,
} from '@tanstack/react-table';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Search, Filter, AlertTriangle, HelpCircle } from 'lucide-react';

/* ─── Column Helper ──────────────────────────────────────────────────────── */
const columnHelper = createColumnHelper<AssetRoute>();

/* ─── Static Data ────────────────────────────────────────────────────────── */
const distributionData = [
  { name: 'REST_PUBLIC', value: 64, color: '#6366F1' },
  { name: 'GRAPHQL_INTERNAL', value: 22, color: '#14B8A6' },
  { name: 'GRPC_LEGACY', value: 14, color: '#A1A1AA' },
];

const recommendations = [
  {
    id: 1,
    level: 'CRITICAL',
    text: 'Patch Zombie API /v1/users immediately',
    ruleId: 'SCHEMA_VIOLATION',
    dotColor: 'bg-rose-400',
  },
  {
    id: 2,
    level: 'WARNING',
    text: 'Deprecate shadow endpoint /api/legacy/auth',
    ruleId: 'DRIFT_DETECTED',
    dotColor: 'bg-amber-400',
  },
  {
    id: 3,
    level: 'INFO',
    text: 'Compliance drift on endpoint /srv/api/v2/user-profile',
    ruleId: 'LATENCY_SPIKE',
    dotColor: 'bg-blue-400',
  },
] as const;

const COMPLIANCE_DOT: Record<string, string> = {
  SECURE: 'bg-emerald-400',
  SHADOW_DRIFT: 'bg-amber-400',
  ZOMBIE_EXCEPTION: 'bg-rose-400',
};

/* ─── Page Component ─────────────────────────────────────────────────────── */
export default function ReportsAndAnalysis() {
  const dispatch = useAppDispatch();
  const routes = useAppSelector((state) => state.asset.routes);
  const complianceFilter = useAppSelector((state) => state.asset.complianceFilter);
  const searchTerm = useAppSelector((state) => state.asset.searchTerm);

  const [sorting, setSorting] = React.useState<SortingState>([]);

  /* ── Filtered data via useMemo ─────────────────────────────────────────── */
  const filteredData = useMemo(() => {
    return routes.filter((asset) => {
      const matchesSearch =
        asset.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.target.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesCompliance =
        complianceFilter === 'ALL' || (asset.compliance_state ?? asset.complianceState) === complianceFilter;
      return matchesSearch && matchesCompliance;
    });
  }, [routes, searchTerm, complianceFilter]);

  /* ── TanStack Table columns ────────────────────────────────────────────── */
  const columns = useMemo(
    () => [
      columnHelper.accessor('path', {
        header: 'BASE PATH',
        cell: (info) => (
          <span className="font-mono text-[11px] text-on-surface-variant">{info.getValue()}</span>
        ),
      }),
      columnHelper.accessor('target', {
        header: 'TARGET ROUTE',
        cell: (info) => (
          <span className="font-mono text-[11px] text-on-surface font-medium">{info.getValue()}</span>
        ),
      }),
      columnHelper.accessor('method', {
        header: 'METHOD',
        cell: (info) => (
          <span className="text-[11px] font-mono text-on-surface">
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor('compliance_state', {
        header: 'COMPLIANCE',
        cell: (info) => {
          const st = info.getValue() ?? info.row.original.complianceState ?? 'SECURE';
          return (
            <span className="inline-flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${COMPLIANCE_DOT[st]}`} />
              <span className="text-[11px] text-on-surface-variant">{st}</span>
            </span>
          );
        },
      }),
      columnHelper.accessor('added_latency', {
        header: 'METRICS',
        cell: (info) => {
          const row = info.row.original;
          return (
            <span className="font-mono text-[11px] text-on-surface-variant">
              {info.getValue() ?? row.addedLatency} / {(row.error_rate ?? row.errorRate)}% err
            </span>
          );
        },
      }),
    ],
    [],
  );

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  /* ── Render ────────────────────────────────────────────────────────────── */
  return (
    <div className="p-5 space-y-4">
      {/* ═══════ 1. Toolbar ═══════ */}
      <div className="bg-bg-surface border border-border-grid rounded-lg p-3 flex justify-between items-center">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-on-surface-variant" />
            <span className="text-sm font-medium text-on-surface-variant">Compliance</span>
          </div>
          <div className="flex gap-2">
            {(['ALL', 'SECURE', 'SHADOW_DRIFT', 'ZOMBIE_EXCEPTION'] as const).map((status) => (
              <button
                key={status}
                onClick={() => dispatch(setComplianceFilter(status))}
                className={`text-xs font-medium rounded-md px-3 py-1.5 border transition-colors cursor-pointer font-sans ${
                  complianceFilter === status
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border-grid bg-bg-canvas text-on-surface-variant hover:text-on-surface'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
        <span className="text-xs text-on-surface-variant">ALIE Algorithm: Operational</span>
      </div>

      {/* ═══════ 2. Top Grid ═══════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ── Left: API Distribution Donut ── */}
        <section className="bg-bg-surface border border-border-grid rounded-lg flex flex-col min-h-[340px]">
          <div className="p-4 flex justify-between items-center border-b border-border-grid">
            <span className="text-sm font-semibold text-on-surface">API Distribution</span>
            <HelpCircle className="w-4 h-4 text-on-surface-variant" />
          </div>

          <div className="flex-grow p-4 flex flex-col md:flex-row items-center justify-center gap-8">
            {/* Donut Chart */}
            <div className="w-44 h-44 relative flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgb(var(--bg-surface))',
                      borderColor: 'rgb(var(--border-grid))',
                      fontFamily: 'var(--font-sans, ui-sans-serif, system-ui, sans-serif)',
                      fontSize: '12px',
                      borderRadius: '8px',
                    }}
                  />
                  <Pie
                    data={distributionData}
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={72}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {distributionData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.color}
                        stroke="rgb(var(--bg-surface))"
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-mono text-2xl font-bold text-on-surface">1,204</span>
                <span className="text-[10px] text-on-surface-variant font-sans">Endpoints</span>
              </div>
            </div>

            {/* Legend */}
            <div className="flex-grow w-full space-y-3">
              {distributionData.map((item, idx) => (
                <div
                  key={idx}
                  className="flex justify-between items-center"
                >
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="text-sm text-on-surface font-sans">{item.name}</span>
                  </div>
                  <span className="text-sm font-medium text-on-surface-variant font-sans">
                    {item.value}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Right: Actionable Recommendations ── */}
        <section className="bg-bg-surface border border-border-grid rounded-lg flex flex-col min-h-[340px]">
          <div className="p-4 flex justify-between items-center border-b border-border-grid">
            <span className="text-sm font-semibold text-on-surface">Recommendations</span>
            <AlertTriangle className="w-4 h-4 text-on-surface-variant" />
          </div>

          <div className="flex-grow p-4 flex flex-col justify-between">
            <div className="divide-y divide-border-grid/50">
              {recommendations.map((rec) => (
                <div
                  key={rec.id}
                  className="flex items-start justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 mt-1.5 ${rec.dotColor}`} />
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="text-sm text-on-surface">{rec.text}</span>
                      <span className="text-xs text-on-surface-variant font-mono">{rec.ruleId}</span>
                    </div>
                  </div>
                  <span className="text-[10px] text-on-surface-variant bg-surface-container rounded-md px-2 py-0.5 flex-shrink-0">
                    {rec.level}
                  </span>
                </div>
              ))}
            </div>

            <div className="text-xs text-on-surface-variant leading-relaxed border-t border-border-grid/50 pt-3 mt-3">
              Rules are updated dynamically via CI/CD integrations mapping semantic AST
              parsers to route signatures.
            </div>
          </div>
        </section>
      </div>

      {/* ═══════ 3. Active API Inventory Table ═══════ */}
      <section className="bg-bg-surface border border-border-grid rounded-lg flex flex-col">
        <div className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-border-grid gap-3">
          <span className="text-sm font-semibold text-on-surface">Active API Inventory</span>

          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant" />
            <input
              type="text"
              placeholder="Filter by path..."
              value={searchTerm}
              onChange={(e) => dispatch(setSearchTerm(e.target.value))}
              className="bg-bg-canvas border border-border-grid rounded-md pl-8 pr-3 py-1.5 text-sm text-on-surface font-sans placeholder:text-on-surface-variant outline-none focus:border-primary w-56"
            />
          </div>
        </div>

        {/* Headless Table */}
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left border-collapse">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr
                  key={headerGroup.id}
                  className="border-b border-border-grid"
                >
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getToggleSortingHandler()}
                      className="p-3 text-xs font-medium text-on-surface-variant uppercase tracking-wider bg-surface-container font-sans cursor-pointer select-none hover:text-on-surface transition-colors"
                    >
                      <div className="flex items-center gap-1.5">
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                        {{
                          asc: ' ▲',
                          desc: ' ▼',
                        }[header.column.getIsSorted() as string] ?? null}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-border-grid/30">
              {table.getRowModel().rows.length > 0 ? (
                table.getRowModel().rows.map((row, rowIndex) => (
                  <tr
                    key={row.id}
                    className={`hover:bg-primary/5 transition-colors ${
                      rowIndex % 2 === 1 ? 'bg-surface-container/30' : ''
                    }`}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className="p-3 align-middle"
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={columns.length} className="p-8 text-center text-on-surface-variant text-sm">
                    No matching records found.
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
