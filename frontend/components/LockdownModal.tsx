'use client';

import { AlertTriangle, X } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '../redux/hooks';
import { setShowLockdownModal, setLockdown } from '../redux/systemSlice';

export default function LockdownModal() {
  const dispatch = useAppDispatch();
  const show = useAppSelector((s) => s.system.showLockdownModal);

  if (!show) return null;

  const handleConfirm = () => {
    dispatch(setLockdown(true));
    dispatch(setShowLockdownModal(false));
  };

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center modal-backdrop bg-black/40 animate-fade-in">
      <div className="w-full max-w-sm mx-4 bg-bg-surface border border-border-grid rounded-xl shadow-modal animate-slide-up">
        {/* Header */}
        <div className="flex items-start justify-between px-5 pt-5 pb-4">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 w-9 h-9 rounded-lg bg-rose-500/10 flex items-center justify-center mt-0.5">
              <AlertTriangle size={16} className="text-rose-500" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-on-surface">Emergency Lockdown</h3>
              <p className="text-xs text-on-surface-variant mt-1 leading-relaxed">
                This will immediately block all ingress traffic and engage a deny-all policy across all API gateways. This action cannot be automatically reversed.
              </p>
            </div>
          </div>
          <button
            onClick={() => dispatch(setShowLockdownModal(false))}
            className="flex-shrink-0 p-1 rounded-md text-on-surface-variant hover:bg-surface-container transition-colors ml-2"
          >
            <X size={14} />
          </button>
        </div>

        {/* Warning box */}
        <div className="mx-5 mb-4 px-3 py-2.5 rounded-lg bg-rose-500/8 border border-rose-500/20">
          <p className="text-xs text-rose-500 font-mono leading-relaxed">
            AFFECTED: 247 routes · 5 active traps · All ingress gateways
          </p>
        </div>

        {/* Actions */}
        <div className="flex gap-2 px-5 pb-5">
          <button
            onClick={() => dispatch(setShowLockdownModal(false))}
            className="flex-1 px-4 py-2 text-sm rounded-lg border border-border-grid text-on-surface-variant hover:bg-surface-container transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            className="flex-1 px-4 py-2 text-sm rounded-lg bg-rose-500 text-white font-medium hover:bg-rose-600 transition-colors"
          >
            Initiate Lockdown
          </button>
        </div>
      </div>
    </div>
  );
}
