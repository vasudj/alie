import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { SystemMetrics, ScanHistoryEntry } from '../types';

interface SystemState {
  metrics: SystemMetrics;
  trafficInterception: boolean;
  autoKillMitigation: boolean;
  isLocked: boolean;
  lockdownLogs: string[];
  isScanning: boolean;
  scanStatus: string | null;
  scanHistory: ScanHistoryEntry[];
  // UI panel / modal state
  showScanModal: boolean;
  showLockdownModal: boolean;
  showSettingsPanel: boolean;
  showNotificationsPanel: boolean;
}

const initialState: SystemState = {
  metrics: {
    risk_score: 42,
    shadow_api_percent: 98,
    incident_discovery_time: '<60s',
    added_latency: '<1ms',
    threats_neutralized: 1284,
    total_apis: 247,
    active_traps: 5,
  },
  trafficInterception: true,
  autoKillMitigation: false,
  isLocked: false,
  lockdownLogs: [],
  isScanning: false,
  scanStatus: null,
  scanHistory: [
    { id: 'SCN-001', created_at: '2026-05-27 09:15 UTC', scan_target: 'core-banking-api-v2', total_apis_scanned: 1204, vulnerabilities_found: 3, engine_status: 'Completed' as const },
    { id: 'SCN-002', created_at: '2026-05-27 14:30 UTC', scan_target: 'payment-gateway-v1',  total_apis_scanned: 487,  vulnerabilities_found: 0, engine_status: 'Completed' as const },
    { id: 'SCN-003', created_at: '2026-05-28 08:00 UTC', scan_target: 'identity-service',     total_apis_scanned: 312,  vulnerabilities_found: 1, engine_status: 'Completed' as const },
    { id: 'SCN-004', created_at: '2026-05-28 16:45 UTC', scan_target: 'core-banking-api-v2', total_apis_scanned: 1204, vulnerabilities_found: 2, engine_status: 'Completed' as const },
  ],
  showScanModal: false,
  showLockdownModal: false,
  showSettingsPanel: false,
  showNotificationsPanel: false,
};

const systemSlice = createSlice({
  name: 'system',
  initialState,
  reducers: {
    toggleTrafficInterception(state) {
      state.trafficInterception = !state.trafficInterception;
    },
    toggleAutoKill(state) {
      state.autoKillMitigation = !state.autoKillMitigation;
    },
    setLockdown(state, action: PayloadAction<boolean>) {
      state.isLocked = action.payload;
      if (!action.payload) state.lockdownLogs = [];
    },
    addLockdownLog(state, action: PayloadAction<string>) {
      state.lockdownLogs = [...state.lockdownLogs.slice(-14), action.payload];
    },
    initLockdownLogs(state) {
      state.lockdownLogs = [
        'INITIATING GLOBAL LOCKDOWN ROUTINE...',
        'SHUTTING DOWN INGRESS GATEWAYS...',
        'ENGAGING ALIE DENY-ALL PROXIES...',
        'FLUSHING EDGE GATEWAY CACHE...',
        'ACTIVE DEFENSE MESH LEVEL 5: ARMED.',
      ];
    },
    updateMetrics(state, action: PayloadAction<Partial<SystemMetrics>>) {
      state.metrics = { ...state.metrics, ...action.payload };
    },
    incrementThreats(state) {
      state.metrics.threats_neutralized = (state.metrics.threats_neutralized ?? 0) + 1;
    },
    setScanning(state, action: PayloadAction<boolean>) {
      state.isScanning = action.payload;
    },
    setScanStatus(state, action: PayloadAction<string | null>) {
      state.scanStatus = action.payload;
    },
    addScanHistory(state, action: PayloadAction<ScanHistoryEntry>) {
      state.scanHistory = [action.payload, ...state.scanHistory];
    },
    // ── UI Modal / Panel toggles ─────────────────────────────────────────
    setShowScanModal(state, action: PayloadAction<boolean>) {
      state.showScanModal = action.payload;
    },
    setShowLockdownModal(state, action: PayloadAction<boolean>) {
      state.showLockdownModal = action.payload;
    },
    setShowSettingsPanel(state, action: PayloadAction<boolean>) {
      state.showSettingsPanel = action.payload;
      if (action.payload) state.showNotificationsPanel = false;
    },
    setShowNotificationsPanel(state, action: PayloadAction<boolean>) {
      state.showNotificationsPanel = action.payload;
      if (action.payload) state.showSettingsPanel = false;
    },
  },
});

export const {
  toggleTrafficInterception,
  toggleAutoKill,
  setLockdown,
  addLockdownLog,
  initLockdownLogs,
  updateMetrics,
  incrementThreats,
  setScanning,
  setScanStatus,
  addScanHistory,
  setShowScanModal,
  setShowLockdownModal,
  setShowSettingsPanel,
  setShowNotificationsPanel,
} = systemSlice.actions;

export default systemSlice.reducer;
