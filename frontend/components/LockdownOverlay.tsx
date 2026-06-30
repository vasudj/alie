'use client';

import { useEffect, useRef } from 'react';
import { ShieldOff, X } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '../redux/hooks';
import { setLockdown, addLockdownLog, initLockdownLogs } from '../redux/systemSlice';

const BLOCKED_MESSAGES = [
  'BLOCKED  45.12.90.11:443  →  /api/v1/auth/exchange',
  'BLOCKED  203.0.113.5:8080  →  /admin/panel/config',
  'BLOCKED  91.108.56.130:443  →  /api/v2/messages',
  'DENIED   34.117.59.81:80  →  /wp-admin.php',
  'BLOCKED  142.250.190.46:443  →  /api/v4/search/global',
  'REJECTED TLS handshake from 172.16.89.231:9090',
  'BLOCKED  10.0.0.12:443  →  /config/remote-shell',
  'TERMINATED session SID-4f2a9c (SLOWLORIS detected)',
  'DENIED DNS lookup → attacker-c2.darknet.io',
  'BLOCKED  192.168.1.55:3000  →  /api/v3/debug-log',
];

export default function LockdownOverlay() {
  const dispatch = useAppDispatch();
  const isLocked = useAppSelector((s) => s.system.isLocked);
  const lockdownLogs = useAppSelector((s) => s.system.lockdownLogs);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isLocked) {
      dispatch(initLockdownLogs());
      intervalRef.current = setInterval(() => {
        const msg = BLOCKED_MESSAGES[Math.floor(Math.random() * BLOCKED_MESSAGES.length)];
        dispatch(addLockdownLog(msg));
      }, 1800);
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isLocked, dispatch]);

  useEffect(() => {
    terminalRef.current?.scrollTo({ top: terminalRef.current.scrollHeight, behavior: 'smooth' });
  }, [lockdownLogs]);

  if (!isLocked) return null;

  return (
    <div className="fixed inset-0 z-[999] flex items-center justify-center modal-backdrop bg-black/60 animate-fade-in">
      <div className="w-full max-w-lg mx-4 bg-bg-surface border border-border-grid rounded-xl shadow-modal animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-grid">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 flex items-center justify-center">
              <ShieldOff size={15} className="text-rose-500" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-on-surface">System Lockdown Active</h3>
              <p className="text-xs text-on-surface-variant mt-0.5">All ingress gateways blocked · Deny-all policy enforced</p>
            </div>
          </div>
          {/* Status dot */}
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 status-pulse" />
            <span className="text-xs text-rose-500 font-medium">LOCKED</span>
          </div>
        </div>

        {/* Terminal */}
        <div className="px-5 py-4">
          <div
            ref={terminalRef}
            className="bg-gray-950 rounded-lg border border-gray-800 p-4 h-52 overflow-y-auto custom-scrollbar"
          >
            {lockdownLogs.map((log, i) => (
              <div key={i} className="flex gap-3 font-mono text-[11px] leading-relaxed">
                <span className="text-gray-600 select-none shrink-0 w-5 text-right">
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span className={
                  log.startsWith('BLOCKED') || log.startsWith('DENIED') || log.startsWith('REJECTED') || log.startsWith('TERMINATED')
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                }>
                  {log}
                </span>
              </div>
            ))}
            <div className="flex gap-3 mt-1">
              <span className="text-gray-600 font-mono text-[11px] select-none w-5 text-right">
                {String(lockdownLogs.length + 1).padStart(2, '0')}
              </span>
              <span className="terminal-cursor" />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 pb-5">
          <button
            onClick={() => dispatch(setLockdown(false))}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg border border-border-grid text-sm text-on-surface-variant hover:bg-surface-container transition-colors"
          >
            <X size={14} />
            Deactivate Lockdown
          </button>
        </div>
      </div>
    </div>
  );
}
