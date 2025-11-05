import React from 'react';
import { ChatEntry, MessageType, SenderType } from '../types';

interface ChatMessageProps {
  entry: ChatEntry;
}

// Helper to safely extract message content using discriminated unions
const getMessageContent = (entry: ChatEntry): string => {
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

export const ChatMessage: React.FC<ChatMessageProps> = React.memo(({ entry }) => {
  const content = getMessageContent(entry);

  const isUser = entry.sender === SenderType.User;

  const alignment = isUser ? 'justify-end' : 'justify-start';
  // Styling: User (Blue glow), Agent (Cyan border/text on dark bg)
  const bubbleStyles = isUser
    ? 'bg-accent-blue/80 text-white shadow-glow-blue border border-accent-blue'
    : 'bg-dark-bg/70 text-text-primary border border-cyber-cyan/50 shadow-glow-cyan';

  const timestampColor = isUser ? 'text-white/70' : 'text-cyber-cyan/70';

  return (
    <div className={`flex ${alignment}`}>
      <div className={`max-w-3xl p-4 rounded-lg ${bubbleStyles} backdrop-blur-sm`}>
        {/* Security: Render content as text. React automatically escapes, preventing XSS. */}
        <p className="whitespace-pre-wrap break-words">
           {content}
        </p>
        <div className={`text-xs font-mono mt-2 text-right ${timestampColor}`}>
            {new Date(entry.message.timestamp).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
});

ChatMessage.displayName = 'ChatMessage';