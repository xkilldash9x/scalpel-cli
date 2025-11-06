import React from 'react';
import { ChatEntry, SenderType } from '../types';
import { getMessageContent } from '../utils/messageUtils';

interface ChatMessageProps {
  entry: ChatEntry;
}

export const ChatMessage: React.FC<ChatMessageProps> = React.memo(({ entry }) => {
  const content = getMessageContent(entry);

  const isUser = entry.sender === SenderType.User;
  // 3. Enhance Optimistic UI: Check delivery status
  const isFailed = entry.status === 'failed';
  const isSending = entry.status === 'sending';

  const alignment = isUser ? 'justify-end' : 'justify-start';
  
  // Styling: Handle User, Agent, and Failed states
  let bubbleStyles = '';
  if (isFailed) {
    // 3. Visual feedback for failed messages
    bubbleStyles = 'bg-red-900/80 text-white border border-red-500 shadow-glow-red';
  } else if (isUser) {
    bubbleStyles = 'bg-accent-blue/80 text-white shadow-glow-blue border border-accent-blue';
  } else {
    // Agent or System
    bubbleStyles = 'bg-dark-bg/70 text-text-primary border border-cyber-cyan/50 shadow-glow-cyan';
  }

  const timestampColor = isUser || isFailed ? 'text-white/70' : 'text-cyber-cyan/70';
  // 3. Visual feedback for sending state (fade out)
  const opacity = isSending ? 'opacity-60' : 'opacity-100';

  return (
    <div className={`flex ${alignment} transition-opacity duration-300 ${opacity}`}>
      <div className={`max-w-3xl p-4 rounded-lg ${bubbleStyles} backdrop-blur-sm`}>
        {/* Security: Render content as text. React automatically escapes, preventing XSS. */}
        <p className="whitespace-pre-wrap break-words">
           {content}
        </p>
        {/* 3. Display error details if failed */}
        {isFailed && entry.error && (
            <p className="text-sm mt-2 text-red-300 font-mono italic" data-testid="error-details">
                Error: {entry.error}
            </p>
        )}
        <div className={`text-xs font-mono mt-2 text-right ${timestampColor}`}>
            {/* 3. Show sending indicator */}
            {isSending && <span className="mr-2 animate-pulse">Sending...</span>}
            {new Date(entry.message.timestamp).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
});

ChatMessage.displayName = 'ChatMessage';