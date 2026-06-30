import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { TelemetryEvent } from '../types';
import { SEED_TELEMETRY } from '../services/api';

interface TelemetryState {
  events: TelemetryEvent[];
  isStreaming: boolean;
  streamIntervalId: number | null;
}

const initialState: TelemetryState = {
  events: SEED_TELEMETRY,
  isStreaming: true,
  streamIntervalId: null,
};

const telemetrySlice = createSlice({
  name: 'telemetry',
  initialState,
  reducers: {
    addEvent(state, action: PayloadAction<TelemetryEvent>) {
      state.events = [action.payload, ...state.events.slice(0, 49)];
    },
    setEvents(state, action: PayloadAction<TelemetryEvent[]>) {
      state.events = action.payload;
    },
    clearEvents(state) {
      state.events = [];
    },
    setStreaming(state, action: PayloadAction<boolean>) {
      state.isStreaming = action.payload;
    },
    setStreamIntervalId(state, action: PayloadAction<number | null>) {
      state.streamIntervalId = action.payload;
    },
  },
});

export const { addEvent, setEvents, clearEvents, setStreaming, setStreamIntervalId } = telemetrySlice.actions;
export default telemetrySlice.reducer;
