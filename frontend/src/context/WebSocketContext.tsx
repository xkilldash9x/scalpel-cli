import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { OutgoingMessagePayload, useWebSocket } from '../hooks/useWebSocket';
import { ChatEntry, ConnectionStatus, MessageType, SenderType, WSMessage } from '../types';

interface WebSocketContextType {
  status: ConnectionStatus;
  history: ChatEntry[];
  sendPrompt: (prompt: string) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [history, setHistory] = useState<ChatEntry[]>([]);

  const addMessageToHistory = useCallback((message: WSMessage, sender: SenderType) => {
    const newEntry: ChatEntry = {
      id: message.request_id || crypto.randomUUID(),
      message,
      sender,
    };
    setHistory((prev) => [...prev, newEntry]);
  }, []);

  const handleMessageReceived = useCallback((message: WSMessage) => {
    switch (message.type) {
        case MessageType.AgentResponse:
            addMessageToHistory(message, SenderType.Agent);
            break;
        case MessageType.StatusUpdate:
            console.log("System Status Update:", message.data.status);
            // Optionally add to history as System message
            break;
    }
  }, [addMessageToHistory]);

  const { status, sendMessage } = useWebSocket(handleMessageReceived);

  const sendPrompt = useCallback((prompt: string) => {
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt) return;

    const payload: OutgoingMessagePayload = {
        type: MessageType.UserPrompt,
        data: { prompt: trimmedPrompt },
    };

    const sentMessage = sendMessage(payload);

    if (sentMessage) {
        addMessageToHistory(sentMessage, SenderType.User);
    } else if (status !== 'OPEN') {
        // Provide feedback if the message failed due to connection issues
        const errorMessage: WSMessage = {
            type: MessageType.SystemError,
            data: { error: 'Connection lost. Failed to send message.' },
            timestamp: new Date().toISOString(),
        };
        addMessageToHistory(errorMessage, SenderType.System);
    }
  }, [sendMessage, addMessageToHistory, status]);

  const contextValue = useMemo(() => ({
    status, history, sendPrompt
  }), [status, history, sendPrompt]);

  return (
    <WebSocketContext.Provider value={contextValue}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWSContext = (): WebSocketContextType => {
    const context = useContext(WebSocketContext);
    if (context === undefined) {
      throw new Error('useWSContext must be used within a WebSocketProvider');
    }
    return context;
};