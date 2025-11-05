import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { WebSocketProvider } from './context/WebSocketContext';
import { StatusIndicator } from './components/StatusIndicator';
import { ChatWindow } from './components/ChatWindow';
import { ChatInput } from './components/ChatInput';
import { GlitchBackground } from './components/GlitchBackground';
import { GlitchHeader } from './components/GlitchHeader';
const App = () => {
    return (_jsx(WebSocketProvider, { children: _jsxs("div", { className: "relative min-h-screen bg-dark-bg flex items-center justify-center p-4 overflow-hidden", children: [_jsx(GlitchBackground, {}), _jsxs("div", { className: "relative z-10 flex flex-col h-[90vh] w-full max-w-5xl bg-dark-surface/90 backdrop-blur-sm shadow-xl shadow-deep-blue/50 border border-deep-blue rounded-lg overflow-hidden transition-shadow duration-500 hover:shadow-glow-cyan", children: [_jsxs("header", { className: "p-4 bg-dark-bg/80 text-text-primary flex justify-between items-center border-b border-deep-blue", children: [_jsx(GlitchHeader, { text: "// SCALPEL_MCP_INTERFACE v2.1" }), _jsx(StatusIndicator, {})] }), _jsx(ChatWindow, {}), _jsx(ChatInput, {})] })] }) }));
};
export default App;
