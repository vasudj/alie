'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Moon, Sun, Bell, Settings } from 'lucide-react';
import ALIELogo from './ALIELogo';
import { useTheme } from './ThemeProvider';
import { useAppDispatch, useAppSelector } from '../redux/hooks';
import { setShowSettingsPanel, setShowNotificationsPanel } from '../redux/systemSlice';

const NAV_ITEMS = [
  { label: 'Command Center',   href: '/' },
  { label: 'Report & Analysis', href: '/reports' },
  { label: 'Live Telemetry',   href: '/telemetry' },
  { label: 'Threat Mitigation', href: '/traps' },
] as const;

export default function Header() {
  const pathname = usePathname();
  const { theme, toggle } = useTheme();
  const dispatch = useAppDispatch();
  const showNotifications = useAppSelector((s) => s.system.showNotificationsPanel);
  const showSettings      = useAppSelector((s) => s.system.showSettingsPanel);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 h-header-height bg-bg-surface border-b border-border-grid flex items-center px-5 gap-6">
      {/* ── Logo ─────────────────────────────────────────────────────── */}
     <Link href="/" className="flex items-center gap-2 shrink-0 text-on-surface hover:text-primary transition-colors">
  <ALIELogo className="w-6 h-6" />
  <span className="font-semibold text-sm tracking-tight">ALIE</span>
</Link>

      {/* ── Nav ──────────────────────────────────────────────────────── */}
      <nav className="flex-1 flex items-center justify-center gap-1">
        {NAV_ITEMS.map(({ label, href }) => {
          const active = href === '/' ? pathname === '/' : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={`relative px-3 h-header-height flex items-center text-sm transition-colors duration-150 ${
                active ? 'text-on-surface font-medium' : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              {label}
              {active && (
                <span className="absolute bottom-0 left-3 right-3 h-[2px] bg-primary rounded-full" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* ── Right Controls ────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 shrink-0">
        {/* Operational status */}
        <div className="flex items-center gap-1.5 mr-3">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-safe status-pulse" />
          <span className="text-[10px] text-on-surface-variant font-mono hidden sm:block">Operational</span>
        </div>

        {/* Night Mode Toggle */}
        <button
          onClick={toggle}
          className="p-2 rounded-lg text-on-surface-variant hover:bg-surface-container hover:text-primary transition-colors"
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
        >
          {theme === 'dark' ? <Sun size={18} strokeWidth={2} /> : <Moon size={18} strokeWidth={2} />}
        </button>

        {/* Notifications */}
        <button
          onClick={() => dispatch(setShowNotificationsPanel(!showNotifications))}
          className={`relative p-2 rounded-lg transition-colors ${
            showNotifications
              ? 'bg-surface-container text-on-surface'
              : 'text-on-surface-variant hover:bg-surface-container hover:text-primary'
          }`}
          aria-label="Notifications"
        >
          <Bell size={18} strokeWidth={2} />
          {/* Unread badge */}
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-rose-500" />
        </button>

        {/* Settings */}
        <button
          onClick={() => dispatch(setShowSettingsPanel(!showSettings))}
          className={`p-2 rounded-lg transition-colors ${
            showSettings
              ? 'bg-surface-container text-on-surface'
              : 'text-on-surface-variant hover:bg-surface-container hover:text-primary'
          }`}
          aria-label="Settings"
        >
          <Settings size={18} strokeWidth={2} />
        </button>
      </div>
    </header>
  );
}
