import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { ChatEntry, ConnectionStatus, DeliveryStatus, MessageType, SenderType, WSMessage } from '../types';

// 2. State Management: Split Contexts

// State Context: For frequently changing values (status, history)
interface WebSocketState {
  status: ConnectionStatus;
  history: ChatEntry[];
}
const WebSocketStateContext = createContext<WebSocketState | undefined>(undefined);

// Actions Context: For stable function references (sendPrompt)
interface WebSocketActions {
  sendPrompt: (prompt: string) => void;
}
const WebSocketActionsContext = createContext<WebSocketActions | undefined>(undefined);


export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [history, setHistory] = useState<ChatEntry[]>([]);

  // 3. Enhance Optimistic UI: Helper to add message with optional initial status
  const addMessageToHistory = useCallback((message: WSMessage, sender: SenderType, deliveryStatus?: DeliveryStatus) => {
    const newEntry: ChatEntry = {
      // Use request_id as the entry ID if available
      id: message.request_id || crypto.randomUUID(),
      message,
      sender,
      status: deliveryStatus,
    };
    setHistory((prev) => [...prev, newEntry]);
  }, []);

  // 3. Enhance Optimistic UI: Helper to update an existing message status
  const updateMessageStatus = useCallback((requestId: string, deliveryStatus: DeliveryStatus, error?: string) => {
    setHistory((prev) =>
      prev.map((entry) =>
        entry.id === requestId ? { ...entry, status: deliveryStatus, error: error || entry.error } : entry
      )
    );
  }, []);

  const handleMessageReceived = useCallback((message: WSMessage) => {
    switch (message.type) {
        case MessageType.AgentResponse:
            // 3. Mark the corresponding user prompt as successfully sent
            if (message.request_id) {
                updateMessageStatus(message.request_id, 'sent');
            }
            addMessageToHistory(message, SenderType.Agent);
            break;
        case MessageType.StatusUpdate:
            console.log("System Status Update:", message.data.status);
            // Optionally add to history as System message
            break;
        // 1. Handle Incoming System Errors
        case MessageType.SystemError:
            if (message.request_id) {
                // 3. Associate the error with the specific message that failed
                updateMessageStatus(message.request_id, 'failed', message.data.error);
            } else {
                // General system error not tied to a request
                addMessageToHistory(message, SenderType.System);
            }
            break;
    }
  }, [addMessageToHistory, updateMessageStatus]);

  const { status, sendMessage } = useWebSocket(handleMessageReceived);

  // 3. Enhance Optimistic UI: Implement optimistic sending
  const sendPrompt = useCallback((prompt: string) => {
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt) return;

    // 1. Create the full message object optimistically
    const requestId = crypto.randomUUID();
    const messageToSend: WSMessage = {
        type: MessageType.UserPrompt,
        data: { prompt: trimmedPrompt },
        timestamp: new Date().toISOString(),
        request_id: requestId,
    } as WSMessage; // Cast because UserPromptMessage requires request_id

    // 2. Add to history immediately with 'sending' status
    addMessageToHistory(messageToSend, SenderType.User, 'sending');

    // 3. Attempt to send via WebSocket hook (which returns boolean success)
    const success = sendMessage(messageToSend);

    // 4. Handle immediate send failure (e.g., socket not ready)
    if (!success) {
        // Update the status of the optimistically added message
        updateMessageStatus(requestId, 'failed', 'Connection lost or socket not ready. Failed to send.');
    }
    // We don't depend on `status` here as `sendMessage` handles the socket state check internally and provides immediate feedback.
  }, [sendMessage, addMessageToHistory, updateMessageStatus]);

  // 2. State Management: Memoize context values
  const stateValue = useMemo(() => ({
    status, history
  }), [status, history]);

  const actionsValue = useMemo(() => ({
    sendPrompt
  }), [sendPrompt]);

  return (
    <WebSocketStateContext.Provider value={stateValue}>
        <WebSocketActionsContext.Provider value={actionsValue}>
            {children}
        </WebSocketActionsContext.Provider>
    </WebSocketStateContext.Provider>
  );
};

// 2. State Management: Custom hooks to consume the split contexts
export const useWebSocketState = (): WebSocketState => {
    const context = useContext(WebSocketStateContext);
    if (context === undefined) {
      throw new Error('useWebSocketState must be used within a WebSocketProvider');
    }
    return context;
};

export const useWebSocketActions = (): WebSocketActions => {
    const context = useContext(WebSocketActionsContext);
    if (context === undefined) {
      throw new Error('useWebSocketActions must be used within a WebSocketProvider');
    }
    return context;
};
