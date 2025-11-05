import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React from 'react';
import { MessageType, SenderType } from '../types';
// Helper to safely extract message content using discriminated unions
const getMessageContent = (entry) => {
    const { message } = entry;
    switch (message.type) {
        case MessageType.UserPrompt:
            return message.data.prompt;
        case MessageType.AgentResponse:
            return message.data.message;
        case MessageType.StatusUpdate:
            return `SYSTEM STATUS: ${message.data.status}`;
        case MessageType.SystemError:
            return `ERROR: ${message.data.error}`;
        default:
            // Fallback for safety, though ideally unreachable with strict typing
            return "[Unrecognized message format]";
    }
};
export const ChatMessage = React.memo(({ entry }) => {
    const content = getMessageContent(entry);
    const isUser = entry.sender === SenderType.User;
    const alignment = isUser ? 'justify-end' : 'justify-start';
    // Styling: User (Blue glow), Agent (Cyan border/text on dark bg)
    const bubbleStyles = isUser
        ? 'bg-accent-blue/80 text-white shadow-glow-blue border border-accent-blue'
        : 'bg-dark-bg/70 text-text-primary border border-cyber-cyan/50 shadow-glow-cyan';
    const timestampColor = isUser ? 'text-white/70' : 'text-cyber-cyan/70';
    return (_jsx("div", { className: `flex ${alignment}`, children: _jsxs("div", { className: `max-w-3xl p-4 rounded-lg ${bubbleStyles} backdrop-blur-sm`, children: [_jsx("p", { className: "whitespace-pre-wrap break-words", children: content }), _jsx("div", { className: `text-xs font-mono mt-2 text-right ${timestampColor}`, children: new Date(entry.message.timestamp).toLocaleTimeString() })] }) }));
});
ChatMessage.displayName = 'ChatMessage';
