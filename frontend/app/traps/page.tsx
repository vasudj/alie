'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { deployTrap, addBan, addForensicPayload } from '../../redux/trapSlice';
import { generateForensicPayload } from '../../services/api';
import { ShieldAlert, Plus, Terminal, Radio, Ban, ChevronRight } from 'lucide-react';

/* ─── Section Header ────────────────────────────────────────────────────────── */
function SectionHeader({ icon: Icon, title, meta }: { icon: React.ElementType; title: string; meta?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between px-4 h-11 border-b border-border-grid bg-surface-container rounded-t-lg shrink-0">
      <div className="flex items-center gap-2">
        <Icon size={14} className="text-on-surface-variant" />
        <span className="text-xs font-sans font-semibold text-on-surface-variant uppercase tracking-wider">{title}</span>
      </div>
      {meta}
    </div>
  );
}

/* ─── Page ──────────────────────────────────────────────────────────────────── */
export default function ThreatMitigation() {
  const dispatch = useAppDispatch();
  const traps        = useAppSelector((s) => s.trap.deployments);
  const bannedLedger = useAppSelector((s) => s.trap.bannedIPs);
  const payloads     = useAppSelector((s) => s.trap.forensicPayloads);
  const isLocked     = useAppSelector((s) => s.system.isLocked);

  const [targetIp,    setTargetIp]    = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [decoyPath,   setDecoyPath]   = useState('');
  const [decoyType,   setDecoyType]   = useState<'Honeypot' | 'Tarpit' | 'Decoy Payload'>('Honeypot');
  const terminalRef = useRef<HTMLDivElement>(null);

  /* ── Auto-scroll terminal ───────────────────────────────────────────── */
  useEffect(() => {
    terminalRef.current?.scrollTo({ top: terminalRef.current.scrollHeight, behavior: 'smooth' });
  }, [payloads]);

  /* ── Forensic stream ────────────────────────────────────────────────── */
  useEffect(() => {
    const interval = setInterval(() => {
      if (!isLocked) dispatch(addForensicPayload(generateForensicPayload()));
    }, 5000);
    return () => clearInterval(interval);
  }, [isLocked, dispatch]);

  const handleDeployDecoy = (e: React.FormEvent) => {
    e.preventDefault();
    if (!decoyPath) return;
    const path = decoyPath.startsWith('/') ? decoyPath : `/${decoyPath}`;
    dispatch(deployTrap({ path, type: decoyType }));
    setDecoyPath('');
  };

  const handleIpBlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetIp) return;
    dispatch(addBan({ ip: targetIp, reason: blockReason || 'Operator Block' }));
    setTargetIp('');
    setBlockReason('');
  };

  const inputCls = "w-full px-3 py-2 rounded-lg border border-border-grid bg-bg-canvas text-sm text-on-surface placeholder:text-on-surface-variant outline-none focus:border-primary focus:ring-1 focus:ring-primary/20 transition-colors";
  const labelCls = "block text-xs font-sans font-medium text-on-surface-variant mb-1.5";

  return (
    <div className="p-5 space-y-4">

      {/* ══ Row 1: Operator Console + Deploy Decoy Traps ══ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Operator Console */}
        <div className="bg-bg-surface border border-border-grid rounded-lg flex flex-col card-shadow">
          <SectionHeader icon={ShieldAlert} title="Manual Operator Console" />
          <div className="p-4 flex flex-col gap-4 flex-1">
            <form onSubmit={handleIpBlock} className="space-y-3">
              <div>
                <label className={labelCls}>IP Address to Block</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.200"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Reason for Block</label>
                <input
                  type="text"
                  placeholder="e.g. Credential Stuffing"
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  className={inputCls}
                />
              </div>
              <button
                type="submit"
                className="w-full py-2 rounded-lg border border-rose-500/20 text-rose-500/80 text-sm font-sans hover:bg-rose-500/5 transition-colors"
              >
                Deploy Block Rule
              </button>
            </form>
          </div>
        </div>

        {/* Deploy Decoy Traps (was TrapNet Deployment Matrix) */}
        <div className="bg-bg-surface border border-border-grid rounded-lg flex flex-col card-shadow">
          <SectionHeader
            icon={Radio}
            title="Deploy Decoy Traps"
            meta={<span className="w-1.5 h-1.5 rounded-full bg-accent-safe status-pulse" />}
          />
          <div className="p-4 flex flex-col gap-4 flex-1">
            <form onSubmit={handleDeployDecoy} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Decoy Path</label>
                  <input
                    type="text"
                    placeholder="/api/v4/trap"
                    value={decoyPath}
                    onChange={(e) => setDecoyPath(e.target.value)}
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Trap Type</label>
                  <select
                    value={decoyType}
                    onChange={(e) => setDecoyType(e.target.value as typeof decoyType)}
                    className={inputCls}
                  >
                    <option value="Honeypot">Honeypot</option>
                    <option value="Tarpit">Tarpit</option>
                    <option value="Decoy Payload">Decoy Payload</option>
                  </select>
                </div>
              </div>
              <button
                type="submit"
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-primary text-on-primary text-sm font-sans font-medium hover:opacity-90 transition-opacity"
              >
                <Plus size={13} />
                Deploy Decoy Endpoint
              </button>
            </form>

            {/* Active decoys */}
            <div className="flex-1 overflow-y-auto custom-scrollbar space-y-1.5 max-h-40">
              {traps.map((trap) => (
                <div key={trap.id} className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-container">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-mono font-medium text-on-surface truncate">{trap.path}</p>
                    <p className="text-[10px] font-sans text-on-surface-variant mt-0.5">
                      {trap.type} · <span className="font-mono">{trap.deployedAt}</span>
                    </p>
                  </div>
                  <div className="ml-2 shrink-0 flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      trap.status === 'TRAPPED'
                        ? 'bg-rose-400'
                        : trap.status === 'ACTIVE'
                          ? 'bg-emerald-400'
                          : 'bg-gray-400'
                    }`} />
                    <span className="text-[10px] font-sans text-on-surface-variant">
                      {trap.status === 'TRAPPED' ? 'Trapped' : trap.status === 'ACTIVE' ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ══ Row 2: Blocked IP History (was Automated Termination Ledger) ══ */}
      <div className="bg-bg-surface border border-border-grid rounded-lg card-shadow overflow-hidden">
        <SectionHeader
          icon={Ban}
          title="Blocked IP History"
          meta={<span className="text-xs font-mono text-on-surface-variant">{bannedLedger.length} entries</span>}
        />
        <div className="overflow-auto custom-scrollbar max-h-52">
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-bg-surface border-b border-border-grid">
              <tr>
                {['Event ID', 'Timestamp', 'Target Vector', 'Source Fingerprint'].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-xs font-sans font-medium text-on-surface-variant uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-grid/50 text-xs">
              {bannedLedger.length > 0 ? bannedLedger.map((ban) => (
                <tr key={ban.id} className="hover:bg-surface-container transition-colors">
                  <td className="px-4 py-2.5 text-primary font-mono font-medium">{ban.id}</td>
                  <td className="px-4 py-2.5 font-mono text-on-surface-variant">
                    {new Date(ban.created_at ?? ban.timestamp ?? Date.now()).toISOString().substring(11, 19)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-on-surface">{ban.url}</td>
                  <td className="px-4 py-2.5 text-on-surface-variant">
                    <span className="font-mono">{ban.ip}</span>
                    <span className="font-sans"> · {ban.reason}</span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center font-sans text-on-surface-variant">
                    No blocked IP events recorded
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ══ Row 3: Forensic Payload Console — FULL WIDTH ══ */}
      <div className="bg-bg-surface border border-border-grid rounded-lg card-shadow overflow-hidden">
        {/* VS Code-style terminal header */}
        <div className="flex items-center justify-between px-4 h-10 bg-surface-container border-b border-border-grid">
          <div className="flex items-center gap-3">
            {/* macOS-style dots */}
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500/60" />
              <span className="w-3 h-3 rounded-full bg-amber-500/60" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/60" />
            </div>
            {/* Tab */}
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-bg-surface border border-border-grid text-xs font-sans text-on-surface-variant">
              <Terminal size={11} />
              <span>Forensic Payload Console</span>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-safe status-pulse" />
            <span className="text-[10px] font-mono text-on-surface-variant">alie@forensics:~/trap_ledger</span>
          </div>
        </div>

        {/* Terminal content */}
        <div
          ref={terminalRef}
          className="h-96 overflow-y-auto custom-scrollbar font-terminal text-[12px] leading-relaxed p-4 bg-gray-950 dark:bg-gray-950"
        >
          <p className="text-gray-500 mb-1">[SYSTEM]: SOCKET_STREAM_INITIALIZED // CAPTURING_BUFFERS...</p>
          <p className="text-gray-600 mb-4">{'─'.repeat(60)}</p>

          {payloads.map((log) => (
            <div key={log.id} className="mb-5">
              {/* Event header */}
              <div className="flex items-center gap-3 mb-1.5">
                <ChevronRight size={11} className="text-gray-500" />
                <span className="text-gray-500 text-[11px]">{log.timestamp}</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400/80">
                  {log.signature}
                </span>
              </div>

              {/* Captured headers */}
              <div className="ml-4 mb-2 px-3 py-2 rounded bg-surface-container border border-border-grid">
                {log.header.split('\\n').map((line, i) => (
                  <p key={i} className="text-[11px]">
                    <span className="text-blue-400">[HEADER]</span>{' '}
                    <span className="text-gray-300">{line}</span>
                  </p>
                ))}
              </div>

              {/* Payload */}
              <div className="ml-4 px-3 py-2 rounded bg-rose-500/[0.04] border border-rose-500/10">
                <p className="text-[10px] text-rose-400/70 mb-1 uppercase tracking-wider">captured payload</p>
                <p className="text-rose-300/90 break-all leading-relaxed">{log.payload}</p>
              </div>
            </div>
          ))}

          {/* Prompt */}
          <div className="flex items-center gap-2 mt-2">
            <span className="text-emerald-500/70">alierisk@root</span>
            <span className="text-gray-500">:</span>
            <span className="text-blue-400">~/trap_ledger</span>
            <span className="text-gray-500">$</span>
            <span className="terminal-cursor" />
          </div>
        </div>
      </div>

    </div>
  );
}
