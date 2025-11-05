import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useWSContext } from '../context/WebSocketContext';
export const StatusIndicator = () => {
    const { status } = useWSContext();
    const getStatusAppearance = (s) => {
        switch (s) {
            case 'OPEN': return { color: 'text-neon-green', bg: 'bg-neon-green shadow-glow-green', pulse: false, label: 'LINK ACTIVE' };
            case 'CONNECTING': return { color: 'text-accent-blue', bg: 'bg-accent-blue shadow-glow-blue', pulse: true, label: 'SYNCING...' };
            case 'CLOSED': return { color: 'text-orange-500', bg: 'bg-orange-500', pulse: false, label: 'OFFLINE' };
            case 'ERROR': return { color: 'text-red-500', bg: 'bg-red-500', pulse: false, label: 'ERROR' };
        }
    };
    const appearance = getStatusAppearance(status);
    return (_jsxs("div", { className: "flex items-center font-mono text-sm", role: "status", "aria-live": "polite", children: [_jsx("span", { className: `w-3 h-3 rounded-full mr-3 ${appearance.bg} ${appearance.pulse ? 'animate-pulse' : ''}` }), _jsx("span", { className: `${appearance.color} tracking-wider`, children: appearance.label })] }));
};
