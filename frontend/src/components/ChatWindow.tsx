import React, { useEffect, useRef } from 'react';
import { useWSContext } from '../context/WebSocketContext';
import { ChatMessage } from './ChatMessage';

export const ChatWindow: React.FC = () => {
  const { history } = useWSContext();
  const endOfMessagesRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  return (
    // Accessibility: Use role="log"
    <div className="flex-1 overflow-y-auto p-4 space-y-4" role="log" aria-label="Chat History">
      {history.map((entry) => (
        <ChatMessage key={entry.id} entry={entry} />
      ))}
      <div ref={endOfMessagesRef} aria-hidden="true" />
    </div>
  );
};