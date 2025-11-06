import React from 'react';
import { useWebSocketState } from '../context/WebSocketContext';
import { ConnectionStatus } from '../types';

export const StatusIndicator: React.FC = () => {
  // 2. State Management: Only subscribe to status changes, preventing re-renders when history updates
  const { status } = useWebSocketState();

  const getStatusAppearance = (s: ConnectionStatus) => {
    switch (s) {
      case 'OPEN': return { color: 'text-neon-green', bg: 'bg-neon-green shadow-glow-green', pulse: false, label: 'LINK ACTIVE' };
      case 'CONNECTING': return { color: 'text-accent-blue', bg: 'bg-accent-blue shadow-glow-blue', pulse: true, label: 'SYNCING...' };
      case 'CLOSED': return { color: 'text-orange-500', bg: 'bg-orange-500', pulse: false, label: 'OFFLINE' };
      case 'ERROR': return { color: 'text-red-500', bg: 'bg-red-500', pulse: false, label: 'ERROR' };
    }
  };

  const appearance = getStatusAppearance(status);

  return (
    <div className="flex items-center font-mono text-sm" role="status" aria-live="polite">
        <span className={`w-3 h-3 rounded-full mr-3 ${appearance.bg} ${appearance.pulse ? 'animate-pulse' : ''}`}></span>
        <span className={`${appearance.color} tracking-wider`}>{appearance.label}</span>
    </div>
  );
};