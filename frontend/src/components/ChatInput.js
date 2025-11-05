import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useCallback } from 'react';
import { useWSContext } from '../context/WebSocketContext';
export const ChatInput = () => {
    const [input, setInput] = useState('');
    const { sendPrompt, status } = useWSContext();
    const isConnected = status === 'OPEN';
    const handleSubmit = useCallback((e) => {
        e.preventDefault();
        const trimmedInput = input.trim();
        if (trimmedInput && isConnected) {
            sendPrompt(trimmedInput);
            setInput('');
        }
    }, [input, isConnected, sendPrompt]);
    // Handle Enter key press for submission (Shift+Enter for new line)
    const handleKeyDown = useCallback((e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSubmit(e);
        }
    }, [handleSubmit]);
    return (_jsx("div", { className: "p-4 border-t border-deep-blue bg-dark-bg/80", children: _jsxs("form", { onSubmit: handleSubmit, className: "flex items-end gap-3", children: [_jsx("textarea", { value: input, onChange: (e) => setInput(e.target.value), onKeyDown: handleKeyDown, rows: 3, placeholder: isConnected ? "// Enter command or prompt..." : "// Awaiting connection...", className: "flex-1 p-3 bg-dark-surface border border-deep-blue rounded-lg focus:outline-none focus:ring-2 focus:ring-cyber-cyan focus:border-cyber-cyan transition duration-150 text-text-primary font-mono resize-none disabled:opacity-50", disabled: !isConnected, "aria-label": "Command Input" }), _jsx("button", { type: "submit", className: `px-6 py-3 rounded-lg font-bold font-mono transition duration-300 shadow-md ${isConnected && input.trim() !== ''
                        ? 'bg-cyber-cyan text-dark-bg hover:bg-neon-green hover:shadow-glow-green'
                        : 'bg-gray-600 text-text-primary/50 cursor-not-allowed'}`, disabled: !isConnected || input.trim() === '', children: "EXECUTE" })] }) }));
};
