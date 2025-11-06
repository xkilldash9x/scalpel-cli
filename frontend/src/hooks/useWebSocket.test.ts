// src/hooks/useWebSocket.test.ts
import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import WS from 'vitest-websocket-mock';
import { useWebSocket } from './useWebSocket';
import { MessageType, WSMessage } from '../types';

// Define the URL the hook will attempt to connect to during tests
const WS_HOST = 'localhost:8080';
const WS_URL = `ws://${WS_HOST}/ws/v1/interact`;

// Mock window.location because the hook uses it to determine the WS URL
const originalLocation = window.location;
beforeAll(() => {
    Object.defineProperty(window, 'location', {
        value: {
            host: WS_HOST,
            protocol: 'http:', // Ensures 'ws:' protocol is used by the hook
        },
        writable: true,
    });
});

afterAll(() => {
    Object.defineProperty(window, 'location', {
        value: originalLocation,
        writable: true,
    });
});

// FIX: Removed unused HookResult type
// type HookResult = ...

describe('useWebSocket Hook Tests', () => {
  let server: WS;
  const mockOnMessageReceived = vi.fn();

  beforeEach(() => {
    server = new WS(WS_URL, { jsonProtocol: true });
    mockOnMessageReceived.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers(); // Ensure real timers are restored
    WS.clean();
  });

  it('should start CONNECTING and transition to OPEN upon successful connection', async () => {
    const { result } = renderHook(() => useWebSocket(mockOnMessageReceived));

    // The initial state should be CONNECTING
    expect(result.current.status).toBe('CONNECTING');

    // Wrap the async update (server connection) in act
    await act(async () => {
        await server.connected;
    });

    // Now the state should be 'OPEN'
    expect(result.current.status).toBe('OPEN');
  }, 10000);

  it('should send a message correctly and return true when connected', async () => {
    const { result } = renderHook(() => useWebSocket(mockOnMessageReceived));

    // Wrap the async connection
    await act(async () => {
      await server.connected;
    });

    expect(result.current.status).toBe('OPEN');

    const messageToSend: WSMessage = {
        type: MessageType.UserPrompt,
        data: { prompt: 'test prompt' },
        timestamp: new Date().toISOString(),
        request_id: 'req-1',
    };

    let sendSuccess: boolean | null = null;
    // Wrap the synchronous action
    act(() => {
        sendSuccess = result.current.sendMessage(messageToSend);
    });

    expect(sendSuccess).toBe(true);
    await expect(server).toReceiveMessage(messageToSend);
  }, 10000);

  it('should return false if sendMessage is called when disconnected', async () => {
    const { result } = renderHook(() => useWebSocket(mockOnMessageReceived));

    // State is 'CONNECTING'
    expect(result.current.status).toBe('CONNECTING');

    const messageToSend: WSMessage = {
        type: MessageType.UserPrompt,
        data: { prompt: 'test' },
        timestamp: new Date().toISOString(),
        request_id: 'req-2',
    };

    let sendSuccess: boolean | null = true;
    // Wrap the synchronous action
    act(() => {
        sendSuccess = result.current.sendMessage(messageToSend);
    });

    expect(sendSuccess).toBe(false);

    // We must consume the pending connection event to avoid
    // an "unwrapped state update" error after the test finishes.
    await act(async () => {
        await server.connected;
    });
  }, 10000);

  it('should attempt to reconnect with exponential backoff', async () => {
    const { result } = renderHook(() => useWebSocket(mockOnMessageReceived));

    // Wrap the initial async connection
    await act(async () => {
      await server.connected;
    });
    expect(result.current.status).toBe('OPEN');

    vi.useFakeTimers();

    // Wrap the state update caused by server.close
    act(() => {
        server.close({ code: 1006, wasClean: false, reason: 'Test closure' });
    });
    expect(result.current.status).toBe('CLOSED');

    // Re-create server for the next connection attempt
    new WS(WS_URL, { jsonProtocol: true });
    
    // Wrap the timer advance, which triggers the reconnect and a state update
    act(() => {
        vi.advanceTimersByTime(1000);
    });
    
    expect(result.current.status).toBe('CONNECTING');

    // Wrap the next state update caused by server.close
    act(() => {
        server.close({ code: 1006, wasClean: false, reason: 'Test closure' });
    });
    expect(result.current.status).toBe('CLOSED');
    
    // Re-create server again
    new WS(WS_URL, { jsonProtocol: true });

    // Wrap the next timer advance
    act(() => {
        vi.advanceTimersByTime(2000);
    });
    
    expect(result.current.status).toBe('CONNECTING');

    vi.useRealTimers();
  }, 15000);
});