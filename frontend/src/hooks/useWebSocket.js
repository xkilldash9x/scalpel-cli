import { useState, useEffect, useRef, useCallback } from 'react';
const INITIAL_RECONNECT_DELAY = 1000;
const MAX_RECONNECT_DELAY = 30000;
const getWsUrl = () => {
    // Security: Enforce WSS if the page is served over HTTPS
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Rely on proxy configuration (e.g., Vite proxy or Nginx) to route correctly
    return `${protocol}//${window.location.host}/ws/v1/interact`;
};
export const useWebSocket = (onMessageReceived) => {
    const [status, setStatus] = useState('CONNECTING');
    const socketRef = useRef(null);
    const retryTimeoutRef = useRef(null);
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
        ws.onclose = (event) => {
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
        ws.onmessage = (event) => {
            try {
                const messageData = JSON.parse(event.data);
                // Runtime validation (Security best practice)
                if (typeof messageData === 'object' && messageData !== null && 'type' in messageData && 'timestamp' in messageData) {
                    onMessageRef.current(messageData);
                }
                else {
                    console.error('Received message with invalid structure', messageData);
                }
            }
            catch (error) {
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
    const sendMessage = useCallback((payload) => {
        if (socketRef.current?.readyState !== WebSocket.OPEN) {
            return null;
        }
        // Security: Use crypto API for strong UUIDs
        const requestId = crypto.randomUUID();
        const messageToSend = {
            ...payload,
            timestamp: new Date().toISOString(),
            request_id: requestId,
        };
        try {
            socketRef.current.send(JSON.stringify(messageToSend));
            return messageToSend;
        }
        catch (error) {
            console.error("Failed to send WebSocket message", error);
            return null;
        }
    }, []);
    return { status, sendMessage };
};
