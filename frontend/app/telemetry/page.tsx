'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { addEvent } from '../../redux/telemetrySlice';
import { incrementThreats } from '../../redux/systemSlice';
import { addBan } from '../../redux/trapSlice';
import { TelemetryEvent } from '../../types';
import { useTelemetrySocket } from '../../hooks/useTelemetrySocket';

/* ─── Format a single event into a terminal log line string ─────────────── */
function formatLogLine(evt: TelemetryEvent): string {
  const ts   = evt.created_at ?? evt.timestamp ?? new Date().toISOString();
  const time = new Date(ts).toISOString().substring(11, 23);
  const sig  = (evt.threat_signature ?? evt.threatSignature) ? ` | SIG: ${evt.threat_signature ?? evt.threatSignature}` : '';
  return `[${time}] ${evt.method.padEnd(6)} ${evt.url} | IP: ${evt.ip} | STATUS: ${evt.action}${sig}`;
}

/* ─── Terminal Log Row ───────────────────────────────────────────────────── */
function LogRow({ evt, isNew }: { evt: TelemetryEvent; isNew: boolean }) {
  const isThreat = !!(evt.threat_signature ?? evt.threatSignature);

  const lineClass = isThreat
    ? 'text-red-700 dark:text-red-500'
    : 'text-[#9ca3af]'; // neutral gray-400 for allowed traffic

  return (
    <div
      className={`flex items-start gap-2 px-4 py-[3px] font-mono text-[12px] leading-relaxed transition-colors ${
        isNew ? 'animate-fade-in' : ''
      }`}
    >
      {isThreat ? (
        <span className="shrink-0 text-red-500 dark:text-red-500 font-bold select-none mt-[1px]">[!]</span>
      ) : (
        <span className="shrink-0 text-[#3d4451] select-none mt-[1px]"> &gt; </span>
      )}
      <span className={lineClass}>{formatLogLine(evt)}</span>
    </div>
  );
}

/* ─── Page ───────────────────────────────────────────────────────────────── */
export default function LiveTelemetry() {
  const dispatch = useAppDispatch();
  const events              = useAppSelector((s) => s.telemetry.events);
  const trafficInterception = useAppSelector((s) => s.system.trafficInterception);
  const autoKillMitigation  = useAppSelector((s) => s.system.autoKillMitigation);
  const isLocked            = useAppSelector((s) => s.system.isLocked);

  const [dateFilter, setDateFilter] = useState('');
  const [newIds,     setNewIds]     = useState<Set<string>>(new Set());
  const bottomRef = useRef<HTMLDivElement>(null);
  const prevCount = useRef(0);

  /* ── Live streaming ──────────────────────────────────────────────── */
  useTelemetrySocket();

  /* ── Auto-scroll when new events arrive ─────────────────────────── */
  useEffect(() => {
    if (events.length !== prevCount.current) {
      prevCount.current = events.length;
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events.length]);

  /* ── Date filter ─────────────────────────────────────────────────── */
  const filteredEvents = useMemo(() => {
    if (!dateFilter) return events;
    return events.filter((e) => (e.created_at ?? e.timestamp ?? '').startsWith(dateFilter));
  }, [events, dateFilter]);

  const threatCount   = filteredEvents.filter((e) => !!(e.threat_signature ?? e.threatSignature)).length;
  const allowedCount  = filteredEvents.length - threatCount;

  return (
    /* Outer shell: stays within the layout's padding but sets its own dark bg */
    <div className="p-5">
      <div className="rounded-xl overflow-hidden border border-[#1a1e2a] shadow-2xl flex flex-col" style={{ minHeight: 'calc(100vh - 120px)' }}>

        {/* ── Terminal window chrome ────────────────────────────────── */}
        <div className="bg-[#1a1e2a] px-4 py-2.5 flex items-center justify-between shrink-0">
          {/* macOS-style dots */}
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-[#ff5f57]" />
            <span className="w-3 h-3 rounded-full bg-[#febc2e]" />
            <span className="w-3 h-3 rounded-full bg-[#28c840]" />
            <span className="ml-3 font-mono text-[12px] text-[#6b7280]">
              alie-core — live-telemetry — event-tail
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Date filter */}
            <input
              type="date"
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="bg-[#0d0f18] border border-[#2a2f3d] rounded-md text-[#9ca3af] font-mono px-2 py-1 text-[11px] outline-none focus:border-[#4b5563]"
            />
            {/* Live dot */}
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-mono text-[11px] text-[#6b7280]">LIVE</span>
            </div>
          </div>
        </div>

        {/* ── Terminal body ─────────────────────────────────────────── */}
        <div className="flex-1 bg-[#050505] overflow-y-auto custom-scrollbar py-3">

          {/* Boot header */}
          <div className="px-4 mb-3 space-y-[2px]">
            <p className="font-mono text-[11px] text-[#3d4451]">
              {'// ALIE Core Engine v4.2 — API Lifecycle Intelligence'}
            </p>
            <p className="font-mono text-[11px] text-[#3d4451]">
              {'// Live event tail active. Streaming all ingress traffic.'}
            </p>
            <p className="font-mono text-[11px] text-[#3d4451]">
              {'─'.repeat(72)}
            </p>
          </div>

          {/* Log lines */}
          {filteredEvents.length > 0 ? (
            filteredEvents.map((evt) => (
              <LogRow key={evt.id} evt={evt} isNew={newIds.has(evt.id)} />
            ))
          ) : (
            <p className="px-4 font-mono text-[12px] text-[#3d4451] italic">
              No events for the selected date range. Waiting for traffic…
            </p>
          )}

          {/* Blinking cursor at bottom */}
          <div className="flex items-center gap-2 px-4 pt-3 pb-2">
            <span className="font-mono text-[12px] text-emerald-500/70">alie@core</span>
            <span className="font-mono text-[12px] text-[#3d4451]">:</span>
            <span className="font-mono text-[12px] text-blue-400/70">~/event-tail</span>
            <span className="font-mono text-[12px] text-[#3d4451]">$</span>
            <span className="terminal-cursor" />
          </div>

          {/* Auto-scroll anchor */}
          <div ref={bottomRef} />
        </div>

        {/* ── Status bar ───────────────────────────────────────────── */}
        <div className="bg-[#0d0f18] border-t border-[#1a1e2a] px-4 py-1.5 flex items-center gap-6 shrink-0">
          <span className="font-mono text-[10px] text-[#6b7280]">
            total: <span className="text-[#9ca3af]">{filteredEvents.length}</span>
          </span>
          <span className="font-mono text-[10px] text-[#6b7280]">
            allowed: <span className="text-emerald-500/80">{allowedCount}</span>
          </span>
          <span className="font-mono text-[10px] text-[#6b7280]">
            threats: <span className="text-red-500">{threatCount}</span>
          </span>
          <span className="ml-auto font-mono text-[10px] text-[#6b7280]">
            interception: <span className={trafficInterception ? 'text-emerald-500' : 'text-[#4b5563]'}>
              {trafficInterception ? 'ON' : 'OFF'}
            </span>
          </span>
        </div>

      </div>
    </div>
  );
}
