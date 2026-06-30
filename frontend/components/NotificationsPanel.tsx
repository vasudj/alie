'use client';

import { X, ShieldAlert, Info, AlertTriangle } from 'lucide-react';
import { useAppDispatch } from '../redux/hooks';
import { setShowNotificationsPanel } from '../redux/systemSlice';

const NOTIFICATIONS = [
  {
    id: 1,
    type: 'critical',
    title: 'SQLi attempt blocked',
    body: 'IP 45.12.90.11 attempted SQL injection on /api/v1/users',
    time: '2 min ago',
    icon: ShieldAlert,
    color: 'text-rose-500',
    bg: 'bg-rose-500/8',
    border: 'border-rose-500/15',
  },
  {
    id: 2,
    type: 'warning',
    title: 'Shadow route discovered',
    body: '/srv/api/v3/debug-log added to asset inventory via scan',
    time: '14 min ago',
    icon: AlertTriangle,
    color: 'text-amber-500',
    bg: 'bg-amber-500/8',
    border: 'border-amber-500/15',
  },
  {
    id: 3,
    type: 'info',
    title: 'TrapNet decoy triggered',
    body: 'Honeypot /api/v4/auth/token_exchange captured 3 requests',
    time: '31 min ago',
    icon: Info,
    color: 'text-blue-500',
    bg: 'bg-blue-500/8',
    border: 'border-blue-500/15',
  },
  {
    id: 4,
    type: 'critical',
    title: 'XSS attempt killed',
    body: 'PUT /config/remote-shell from 201.55.12.8 terminated',
    time: '48 min ago',
    icon: ShieldAlert,
    color: 'text-rose-500',
    bg: 'bg-rose-500/8',
    border: 'border-rose-500/15',
  },
  {
    id: 5,
    type: 'info',
    title: 'Compliance scan complete',
    body: '247 routes analyzed · 2 ZOMBIE_EXCEPTION routes flagged',
    time: '1 hr ago',
    icon: Info,
    color: 'text-blue-500',
    bg: 'bg-blue-500/8',
    border: 'border-blue-500/15',
  },
];

export default function NotificationsPanel() {
  const dispatch = useAppDispatch();

  return (
    <div className="fixed inset-0 z-[150] flex justify-end animate-fade-in">
      {/* Backdrop */}
      <div
        className="flex-1 bg-black/20 modal-backdrop"
        onClick={() => dispatch(setShowNotificationsPanel(false))}
      />

      {/* Panel */}
      <aside className="w-80 h-full bg-bg-surface border-l border-border-grid shadow-panel animate-slide-in-right flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-grid">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-on-surface">Notifications</h2>
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-rose-500/10 text-rose-500">
              {NOTIFICATIONS.filter((n) => n.type === 'critical').length}
            </span>
          </div>
          <button
            onClick={() => dispatch(setShowNotificationsPanel(false))}
            className="p-1.5 rounded-md text-on-surface-variant hover:bg-surface-container transition-colors"
          >
            <X size={14} />
          </button>
        </div>

        {/* Notification list */}
        <div className="flex-1 overflow-y-auto custom-scrollbar divide-y divide-border-grid">
          {NOTIFICATIONS.map(({ id, icon: Icon, title, body, time, color, bg, border }) => (
            <div key={id} className="px-4 py-3.5 hover:bg-surface-container transition-colors cursor-default">
              <div className="flex gap-3">
                <div className={`flex-shrink-0 w-7 h-7 rounded-lg ${bg} border ${border} flex items-center justify-center mt-0.5`}>
                  <Icon size={12} className={color} />
                </div>
                <div className="min-w-0">
                  <p className="text-sm text-on-surface font-medium truncate">{title}</p>
                  <p className="text-xs text-on-surface-variant mt-0.5 leading-relaxed">{body}</p>
                  <p className="text-[10px] text-on-surface-variant mt-1 opacity-60">{time}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border-grid">
          <button className="w-full text-xs text-on-surface-variant hover:text-primary transition-colors text-center">
            Mark all as read
          </button>
        </div>
      </aside>
    </div>
  );
}
