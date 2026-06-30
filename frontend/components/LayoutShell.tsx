'use client';

import { useState } from 'react';
import Header from './Header';
import Sidebar from './Sidebar';
import LockdownOverlay from './LockdownOverlay';
import ScanModal from './ScanModal';
import LockdownModal from './LockdownModal';
import SettingsPanel from './SettingsPanel';
import NotificationsPanel from './NotificationsPanel';
import { useAppSelector } from '../redux/hooks';

const DEFAULT_SIDEBAR_WIDTH = 280;

export default function LayoutShell({ children }: { children: React.ReactNode }) {
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_SIDEBAR_WIDTH);

  const showSettings      = useAppSelector((s) => s.system.showSettingsPanel);
  const showNotifications = useAppSelector((s) => s.system.showNotificationsPanel);
  const showScanModal     = useAppSelector((s) => s.system.showScanModal);
  const showLockdownModal = useAppSelector((s) => s.system.showLockdownModal);

  return (
    <>
      <Header />
      <Sidebar width={sidebarWidth} onWidthChange={setSidebarWidth} />

      {/* Main content — dynamic right padding matches sidebar */}
      <main
        className="pt-header-height min-h-screen transition-[padding-right] duration-150"
        style={{ paddingRight: sidebarWidth }}
      >
        {children}
      </main>

      {/* Global modals & panels */}
      {showScanModal     && <ScanModal />}
      {showLockdownModal && <LockdownModal />}
      {showSettings      && <SettingsPanel />}
      {showNotifications && <NotificationsPanel />}
      <LockdownOverlay />
    </>
  );
}
