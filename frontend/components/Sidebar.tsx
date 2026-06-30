'use client';

import { useCallback, useRef } from 'react';
import { GripVertical, ScanLine } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '../redux/hooks';
import {
  toggleTrafficInterception,
  toggleAutoKill,
  setShowScanModal,
} from '../redux/systemSlice';

/* ─── ToggleRow ────────────────────────────────────────────────────────────── */

function ToggleRow({
  label,
  description,
  active,
  onToggle,
}: {
  label: string;
  description: string;
  active: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <div className="min-w-0">
        <p className="text-sm text-on-surface font-medium">{label}</p>
        <p className="text-xs text-on-surface-variant mt-0.5">{description}</p>
      </div>
      <button
        onClick={onToggle}
        className={`toggle-track mt-0.5 ${active ? 'active' : ''}`}
        role="switch"
        aria-checked={active}
        aria-label={label}
      >
        <span className="toggle-thumb" />
      </button>
    </div>
  );
}

/* ─── Sidebar ───────────────────────────────────────────────────────────────── */

interface SidebarProps {
  width: number;
  onWidthChange: (w: number) => void;
}

export default function Sidebar({ width, onWidthChange }: SidebarProps) {
  const dispatch = useAppDispatch();
  const trafficInterception = useAppSelector((s) => s.system.trafficInterception);
  const autoKillMitigation  = useAppSelector((s) => s.system.autoKillMitigation);
  const isScanning          = useAppSelector((s) => s.system.isScanning);
  const metrics             = useAppSelector((s) => s.system.metrics);

  const isResizing = useRef(false);

  /* ── Drag-to-resize handler ──────────────────────────────────────────── */
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      isResizing.current = true;
      const startX     = e.clientX;
      const startWidth = width;

      const onMove = (ev: MouseEvent) => {
        if (!isResizing.current) return;
        const delta = startX - ev.clientX; // sidebar is on right side
        onWidthChange(Math.min(420, Math.max(200, startWidth + delta)));
      };

      const onUp = () => {
        isResizing.current = false;
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      };

      document.body.style.cursor     = 'col-resize';
      document.body.style.userSelect = 'none';
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    },
    [width, onWidthChange],
  );

  return (
    <aside
      className="fixed right-0 top-header-height bottom-0 bg-bg-surface border-l border-border-grid flex flex-col z-40"
      style={{ width }}
    >
      {/* ── Drag handle (left edge) ──────────────────────────────────── */}
      <div
        className="resize-handle"
        onMouseDown={handleMouseDown}
        title="Drag to resize"
      >
        <GripVertical
          size={12}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-on-surface-variant opacity-30"
        />
      </div>

      {/* ── Title ────────────────────────────────────────────────────── */}
      <div className="px-4 pt-5 pb-4 border-b border-border-grid">
        <p className="text-[10px] font-semibold text-on-surface-variant uppercase tracking-widest">
          Action and Control
        </p>
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {/* ── System Interception Modes ─────────────────────────────── */}
        <div className="px-4 py-2 border-b border-border-grid">
          <p className="text-[10px] font-semibold text-on-surface-variant uppercase tracking-widest pt-3 pb-1">
            Interception Modes
          </p>
          <ToggleRow
            label="Traffic Interception"
            description="Monitor all ingress traffic"
            active={trafficInterception}
            onToggle={() => dispatch(toggleTrafficInterception())}
          />
          <ToggleRow
            label="Auto-Kill Mitigation"
            description="Auto-terminate threat signatures"
            active={autoKillMitigation}
            onToggle={() => dispatch(toggleAutoKill())}
          />
        </div>


        {/* ── Codebase Scan ─────────────────────────────────────────── */}
        <div className="px-4 py-4 border-b border-border-grid">
          <p className="text-[10px] font-semibold text-on-surface-variant uppercase tracking-widest mb-3">
            Security Scan
          </p>
          <button
            onClick={() => dispatch(setShowScanModal(true))}
            disabled={isScanning}
            className={`w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors ${
              isScanning
                ? 'bg-surface-container text-on-surface-variant cursor-not-allowed'
                : 'bg-primary text-on-primary hover:opacity-90'
            }`}
          >
            <ScanLine size={13} />
            {isScanning ? 'Scanning…' : 'Execute Codebase Scan'}
          </button>
        </div>

        {/* ── Active Threats Quick-Stats ─────────────────────────────── */}
        <div className="px-4 py-4">
          <p className="text-[10px] font-semibold text-on-surface-variant uppercase tracking-widest mb-3">
            Live Metrics
          </p>
          <div className="space-y-2">
            {[
              { label: 'Threats Neutralized', value: (metrics.threats_neutralized ?? 0).toLocaleString(), accent: 'text-on-surface' },
              { label: 'Total APIs Monitored', value: metrics.total_apis ?? 0,                             accent: 'text-on-surface' },
              { label: 'Active Traps',         value: metrics.active_traps ?? 0,                           accent: 'text-accent-safe' },
              { label: 'Added Latency',        value: metrics.added_latency ?? '—',                        accent: 'text-accent-safe' },
            ].map(({ label, value, accent }) => (
              <div key={label} className="flex justify-between items-center py-1.5 px-3 rounded-lg bg-surface-container">
                <span className="text-xs text-on-surface-variant">{label}</span>
                <span className={`text-xs font-mono font-semibold ${accent}`}>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Footer ────────────────────────────────────────────────────── */}
      <div className="px-4 py-3 border-t border-border-grid">
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-safe status-pulse" />
          <span className="text-[10px] text-on-surface-variant">Engine operational</span>
        </div>
      </div>
    </aside>
  );
}
