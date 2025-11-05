import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { MessageType, SenderType } from '../types';
const WebSocketContext = createContext(undefined);
export const WebSocketProvider = ({ children }) => {
    const [history, setHistory] = useState([]);
    const addMessageToHistory = useCallback((message, sender) => {
        const newEntry = {
            id: message.request_id || crypto.randomUUID(),
            message,
            sender,
        };
        setHistory((prev) => [...prev, newEntry]);
    }, []);
    const handleMessageReceived = useCallback((message) => {
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
    const sendPrompt = useCallback((prompt) => {
        const trimmedPrompt = prompt.trim();
        if (!trimmedPrompt)
            return;
        const payload = {
            type: MessageType.UserPrompt,
            data: { prompt: trimmedPrompt },
        };
        const sentMessage = sendMessage(payload);
        if (sentMessage) {
            addMessageToHistory(sentMessage, SenderType.User);
        }
        else if (status !== 'OPEN') {
            // Provide feedback if the message failed due to connection issues
            const errorMessage = {
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
    return (_jsx(WebSocketContext.Provider, { value: contextValue, children: children }));
};
export const useWSContext = () => {
    const context = useContext(WebSocketContext);
    if (context === undefined) {
        throw new Error('useWSContext must be used within a WebSocketProvider');
    }
    return context;
};
