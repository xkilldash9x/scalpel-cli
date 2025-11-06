import { useState, useEffect, useRef, useCallback } from 'react';
import { ConnectionStatus, WSMessage } from '../types';

const INITIAL_RECONNECT_DELAY = 1000;
const MAX_RECONNECT_DELAY = 30000;

const getWsUrl = (): string => {
    // Security: Enforce WSS if the page is served over HTTPS
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Rely on proxy configuration (e.g., Vite proxy or Nginx) to route correctly
    return `${protocol}//${window.location.host}/ws/v1/interact`;
};

// The hook now expects the full WSMessage structure when sending.
export const useWebSocket = (onMessageReceived: (message: WSMessage) => void) => {
  const [status, setStatus] = useState<ConnectionStatus>('CONNECTING');
  const socketRef = useRef<WebSocket | null>(null);
  const retryTimeoutRef = useRef<number | null>(null);
  const reconnectDelayRef = useRef(INITIAL_RECONNECT_DELAY);
  const onMessageRef = useRef(onMessageReceived);

  useEffect(() => {
    onMessageRef.current = onMessageReceived;
  }, [onMessageReceived]);

  const connect = useCallback(() => {
    if (socketRef.current && (socketRef.current.readyState === WebSocket.OPEN || socketRef.current.readyState === WebSocket.CONNECTING)) {
        return;
    }

    setStatus('CONNECTING');
    const ws = new WebSocket(getWsUrl());
    socketRef.current = ws;

    ws.onopen = () => {
      setStatus('OPEN');
      reconnectDelayRef.current = INITIAL_RECONNECT_DELAY; // Reset delay on success
      if (retryTimeoutRef.current) {
        window.clearTimeout(retryTimeoutRef.current);
        retryTimeoutRef.current = null;
      }
    };

    ws.onclose = (event: CloseEvent) => {
      setStatus('CLOSED');
      socketRef.current = null;

      // Robust Reconnection Logic with Exponential Backoff
      if (!event.wasClean && retryTimeoutRef.current === null) {
        const delay = reconnectDelayRef.current;
        console.log(`WebSocket closed unexpectedly. Reconnecting in ${delay}ms...`);

        retryTimeoutRef.current = window.setTimeout(() => {
            connect();
            retryTimeoutRef.current = null;
        }, delay);

        // Increase delay for next attempt
        reconnectDelayRef.current = Math.min(delay * 2, MAX_RECONNECT_DELAY);
      }
    };

    ws.onerror = () => {
      setStatus('ERROR');
      ws.close(); // Trigger onclose to initiate reconnection
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const messageData: unknown = JSON.parse(event.data);

        // Runtime validation (Security best practice)
        if (typeof messageData === 'object' && messageData !== null && 'type' in messageData && 'timestamp' in messageData) {
            onMessageRef.current(messageData as WSMessage);
        } else {
            console.error('Received message with invalid structure', messageData);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message', error);
      }
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
        if (socketRef.current) {
            socketRef.current.onclose = null; // Prevent reconnect during cleanup
            socketRef.current.close();
        }
        if (retryTimeoutRef.current) {
            window.clearTimeout(retryTimeoutRef.current);
        }
    };
  }, [connect]);

  // 3. Enhance Optimistic UI: Update signature.
  // Accepts the full message (constructed optimistically in the context) and returns boolean success.
  const sendMessage = useCallback((message: WSMessage): boolean => {
    if (socketRef.current?.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
        socketRef.current.send(JSON.stringify(message));
        return true;
    } catch (error) {
        console.error("Failed to send WebSocket message", error);
        return false;
    }
  }, []);

  return { status, sendMessage };
};