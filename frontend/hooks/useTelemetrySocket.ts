/**
 * useTelemetrySocket — FastAPI WebSocket hook for the ALIE Live Telemetry terminal.
 */

import { useEffect, useRef, useCallback } from 'react';
import { WsTelemetryFrame } from '../types';
import { useAppDispatch } from '../redux/hooks';
import { addEvent } from '../redux/telemetrySlice';
import { incrementThreats } from '../redux/systemSlice';
import { addBan } from '../redux/trapSlice';

const WS_URL = process.env.NEXT_PUBLIC_WS_TELEMETRY_URL ?? 'ws://localhost:8000/ws/telemetry/';

const BACKOFF = {
  initial: 1000,
  multiplier: 2,
  cap: 30000,
  jitter: 500,
};

export function useTelemetrySocket() {
  const dispatch = useAppDispatch();
  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(BACKOFF.initial);
  const intentionalRef = useRef(false);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearRetryTimer = useCallback(() => {
    if (retryTimerRef.current !== null) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
  }, []);

  const closeSocket = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (typeof window === 'undefined') return;
    clearRetryTimer();
    closeSocket();

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        backoffRef.current = BACKOFF.initial;
      };

      ws.onmessage = (evt: MessageEvent<string>) => {
        try {
          const frame: WsTelemetryFrame = JSON.parse(evt.data);
          if (frame.event) {
            const ev = frame.event;
            dispatch(addEvent(ev as any));
            if (ev.threat_signature || (ev as any).threatSignature) {
              dispatch(incrementThreats());
              if (ev.action === 'BANNED' || ev.action === 'BLOCK') {
                dispatch(addBan({ 
                  ip: ev.ip, 
                  reason: ev.threat_signature || (ev as any).threatSignature || 'Security Policy Violation', 
                  url: ev.url 
                }));
              }
            }
          }
        } catch (e) {
          console.error("Failed to parse telemetry frame", e);
        }
      };

      ws.onclose = (evt: CloseEvent) => {
        wsRef.current = null;
        if (intentionalRef.current) return;
        
        const jitter = Math.random() * BACKOFF.jitter;
        const delay = Math.min(backoffRef.current + jitter, BACKOFF.cap);
        backoffRef.current = Math.min(backoffRef.current * BACKOFF.multiplier, BACKOFF.cap);
        retryTimerRef.current = setTimeout(connect, delay);
      };
    } catch (e) {
      console.error("WS init failed", e);
    }
  }, [dispatch, clearRetryTimer, closeSocket]);

  useEffect(() => {
    intentionalRef.current = false;
    connect();
    return () => {
      intentionalRef.current = true;
      clearRetryTimer();
      closeSocket();
    };
  }, [connect, clearRetryTimer, closeSocket]);

  const disconnect = useCallback(() => {
    intentionalRef.current = true;
    clearRetryTimer();
    closeSocket();
  }, [clearRetryTimer, closeSocket]);

  return { disconnect };
}
