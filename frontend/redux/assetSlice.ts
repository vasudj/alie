import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { AssetRoute } from '../types';
import { SEED_ASSETS } from '../services/api';

interface AssetState {
  routes: AssetRoute[];
  complianceFilter: string;
  searchTerm: string;
}

const initialState: AssetState = {
  routes: SEED_ASSETS,
  complianceFilter: 'ALL',
  searchTerm: '',
};

const assetSlice = createSlice({
  name: 'asset',
  initialState,
  reducers: {
    addRoute(state, action: PayloadAction<AssetRoute>) {
      // Avoid duplicates by path
      if (!state.routes.some(r => r.path === action.payload.path)) {
        state.routes = [action.payload, ...state.routes];
      }
    },
    setComplianceFilter(state, action: PayloadAction<string>) {
      state.complianceFilter = action.payload;
    },
    setSearchTerm(state, action: PayloadAction<string>) {
      state.searchTerm = action.payload;
    },
  },
});

export const { addRoute, setComplianceFilter, setSearchTerm } = assetSlice.actions;
export default assetSlice.reducer;
