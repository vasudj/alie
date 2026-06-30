'use client';

import { X, Moon, Sun, Shield, Database, Bell, Clock, Zap } from 'lucide-react';
import { useAppDispatch } from '../redux/hooks';
import { setShowSettingsPanel } from '../redux/systemSlice';
import { useTheme } from './ThemeProvider';

export default function SettingsPanel() {
  const dispatch = useAppDispatch();
  const { theme, toggle } = useTheme();

  return (
    <div className="fixed inset-0 z-[150] flex justify-end animate-fade-in">
      {/* Backdrop */}
      <div
        className="flex-1 bg-black/20 modal-backdrop"
        onClick={() => dispatch(setShowSettingsPanel(false))}
      />

      {/* Panel */}
      <aside className="w-80 h-full bg-bg-surface border-l border-border-grid shadow-panel animate-slide-in-right flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-grid">
          <h2 className="text-sm font-semibold text-on-surface">Settings</h2>
          <button
            onClick={() => dispatch(setShowSettingsPanel(false))}
            className="p-1.5 rounded-md text-on-surface-variant hover:bg-surface-container transition-colors"
          >
            <X size={14} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar">
          {/* Appearance */}
          <div className="px-5 py-4 border-b border-border-grid">
            <h3 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-3">Appearance</h3>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                {theme === 'dark' ? (
                  <Moon size={15} className="text-on-surface-variant" />
                ) : (
                  <Sun size={15} className="text-on-surface-variant" />
                )}
                <div>
                  <p className="text-sm text-on-surface">Night Mode</p>
                  <p className="text-xs text-on-surface-variant">
                    {theme === 'dark' ? 'Dark theme active' : 'Light theme active'}
                  </p>
                </div>
              </div>
              <button
                onClick={toggle}
                className={`toggle-track ${theme === 'dark' ? 'active' : ''}`}
                role="switch"
                aria-checked={theme === 'dark'}
              >
                <span className="toggle-thumb" />
              </button>
            </div>
          </div>

          {/* Data */}
          <div className="px-5 py-4 border-b border-border-grid">
            <h3 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-3">Data & Streams</h3>
            <div className="space-y-3">
              {[
                { icon: Zap, label: 'Live Event Stream', desc: 'Poll interval: 3.5s', enabled: true },
                { icon: Clock, label: 'Forensic Stream',  desc: 'Poll interval: 5s',   enabled: true },
                { icon: Database, label: 'Asset Sync',   desc: 'On-demand scan',       enabled: false },
              ].map(({ icon: Icon, label, desc, enabled }) => (
                <div key={label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <Icon size={14} className="text-on-surface-variant" />
                    <div>
                      <p className="text-sm text-on-surface">{label}</p>
                      <p className="text-xs text-on-surface-variant">{desc}</p>
                    </div>
                  </div>
                  <div className={`w-1.5 h-1.5 rounded-full ${enabled ? 'bg-accent-safe' : 'bg-on-surface-variant opacity-30'}`} />
                </div>
              ))}
            </div>
          </div>

          {/* Security */}
          <div className="px-5 py-4">
            <h3 className="text-xs font-semibold text-on-surface-variant uppercase tracking-wider mb-3">Security Engine</h3>
            <div className="space-y-2.5">
              {[
                'ALIE Core Engine v4.2',
                'ALIE Edge Proxy v3.4',
                'ALIE Reverse Proxy v1.25',
                'ALIE TrapNet Engine v2.1',
              ].map((item) => (
                <div key={item} className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-surface-container">
                  <div className="flex items-center gap-2">
                    <Shield size={12} className="text-accent-safe" />
                    <span className="text-xs text-on-surface font-mono">{item}</span>
                  </div>
                  <span className="text-[10px] text-accent-safe font-medium">Active</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border-grid">
          <p className="text-[10px] text-on-surface-variant text-center">
            ALIE v4.2.0 · Build 2026.05.29
          </p>
        </div>
      </aside>
    </div>
  );
}
