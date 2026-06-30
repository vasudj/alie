import { configureStore } from '@reduxjs/toolkit';
import telemetryReducer from './telemetrySlice';
import assetReducer from './assetSlice';
import trapReducer from './trapSlice';
import systemReducer from './systemSlice';

export const store = configureStore({
  reducer: {
    telemetry: telemetryReducer,
    asset: assetReducer,
    trap: trapReducer,
    system: systemReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false,
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
