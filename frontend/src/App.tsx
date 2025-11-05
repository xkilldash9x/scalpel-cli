import React from 'react';
import { WebSocketProvider } from './context/WebSocketContext';
import { StatusIndicator } from './components/StatusIndicator';
import { ChatWindow } from './components/ChatWindow';
import { ChatInput } from './components/ChatInput';
import { GlitchBackground } from './components/GlitchBackground';
import { GlitchHeader } from './components/GlitchHeader';

const App: React.FC = () => {
  return (
    <WebSocketProvider>
      <div className="relative min-h-screen bg-dark-bg flex items-center justify-center p-4 overflow-hidden">
        <GlitchBackground />

        {/* Main Interface Container with subtle glow effect and backdrop blur */}
        <div className="relative z-10 flex flex-col h-[90vh] w-full max-w-5xl bg-dark-surface/90 backdrop-blur-sm shadow-xl shadow-deep-blue/50 border border-deep-blue rounded-lg overflow-hidden transition-shadow duration-500 hover:shadow-glow-cyan">

          {/* Header with randomized glitching title */}
          <header className="p-4 bg-dark-bg/80 text-text-primary flex justify-between items-center border-b border-deep-blue">
            <GlitchHeader text="// SCALPEL_MCP_INTERFACE v2.1" />
            <StatusIndicator />
          </header>

          <ChatWindow />
          <ChatInput />
        </div>
      </div>
    </WebSocketProvider>
  );
};

export default App;