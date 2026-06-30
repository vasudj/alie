import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { TrapDeployment, BannedIP, ForensicPayload } from '../types';
import { SEED_TRAPS, SEED_BANS, THREAT_PAYLOADS } from '../services/api';

interface TrapState {
  deployments: TrapDeployment[];
  bannedIPs: BannedIP[];
  forensicPayloads: ForensicPayload[];
  forensicIntervalId: number | null;
}

const INITIAL_FORENSICS: ForensicPayload[] = [
  {
    id: '1',
    created_at: new Date(Date.now() - 10000).toISOString(),
    timestamp: new Date(Date.now() - 10000).toISOString().replace('T', ' ').substring(11, 19),
    header: 'Host: internal.risk-engine.alie.io\\nUser-Agent: Mozilla/5.0 (SQLmap/v1.4.10)\\nX-Forwarded-For: 203.0.113.195',
    payload_data: THREAT_PAYLOADS[0],
    payload: THREAT_PAYLOADS[0],
    signature: 'SQLi',
  },
  {
    id: '2',
    created_at: new Date(Date.now() - 5000).toISOString(),
    timestamp: new Date(Date.now() - 5000).toISOString().replace('T', ' ').substring(11, 19),
    header: 'Host: secure-gateway.alie.io\\nUser-Agent: Curl/7.68.0\\nAccept: */*',
    payload_data: THREAT_PAYLOADS[1],
    payload: THREAT_PAYLOADS[1],
    signature: 'XSS',
  },
];

const initialState: TrapState = {
  deployments: SEED_TRAPS,
  bannedIPs: SEED_BANS,
  forensicPayloads: INITIAL_FORENSICS,
  forensicIntervalId: null,
};

let trapCounter = SEED_TRAPS.length;
let banCounter  = SEED_BANS.length;

const trapSlice = createSlice({
  name: 'trap',
  initialState,
  reducers: {
    deployTrap(state, action: PayloadAction<{ path: string; type: TrapDeployment['type'] }>) {
      trapCounter++;
      const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const newTrap: TrapDeployment = {
        id: `TRP-${String(trapCounter).padStart(3, '0')}`,
        path: action.payload.path,
        type: action.payload.type,
        status: 'ACTIVE',
        deployed_at: ts,
        deployedAt:  ts,
      };
      state.deployments = [newTrap, ...state.deployments];
    },
    addBan(state, action: PayloadAction<{ ip: string; reason: string; url?: string }>) {
      banCounter++;
      const now = new Date().toISOString();
      const newBan: BannedIP = {
        id: `BAN-${String(banCounter).padStart(3, '0')}`,
        created_at: now,
        timestamp:  now,
        url:    action.payload.url || 'MANUAL_INTERVENTION_RULE',
        ip:     action.payload.ip,
        reason: action.payload.reason || 'Operator Blacklisted',
      };
      state.bannedIPs = [newBan, ...state.bannedIPs];
    },
    addForensicPayload(state, action: PayloadAction<ForensicPayload>) {
      state.forensicPayloads = [...state.forensicPayloads.slice(-9), action.payload];
    },
    setForensicIntervalId(state, action: PayloadAction<number | null>) {
      state.forensicIntervalId = action.payload;
    },
  },
});

export const { deployTrap, addBan, addForensicPayload, setForensicIntervalId } = trapSlice.actions;
export default trapSlice.reducer;
