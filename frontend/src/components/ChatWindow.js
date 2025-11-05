import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useRef } from 'react';
import { useWSContext } from '../context/WebSocketContext';
import { ChatMessage } from './ChatMessage';
export const ChatWindow = () => {
    const { history } = useWSContext();
    const endOfMessagesRef = useRef(null);
    // Auto-scroll to bottom
    useEffect(() => {
        endOfMessagesRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [history]);
    return (
    // Accessibility: Use role="log"
    _jsxs("div", { className: "flex-1 overflow-y-auto p-4 space-y-4", role: "log", "aria-label": "Chat History", children: [history.map((entry) => (_jsx(ChatMessage, { entry: entry }, entry.id))), _jsx("div", { ref: endOfMessagesRef, "aria-hidden": "true" })] }));
};
