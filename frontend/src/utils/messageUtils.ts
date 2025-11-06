import { ChatEntry, MessageType } from '../types';

// Helper to safely extract message content using discriminated unions.
export const getMessageContent = (entry: ChatEntry): string => {
    const { message } = entry;

    // Note: We display the original content even if the status is 'failed'.
    // The ChatMessage component handles the visual representation of the failure.

    switch (message.type) {
        case MessageType.UserPrompt:
            return message.data.prompt;
        case MessageType.AgentResponse:
            return message.data.message;
        case MessageType.StatusUpdate:
             return `SYSTEM STATUS: ${message.data.status}`;
        case MessageType.SystemError:
            // 1. Handle Incoming System Errors: Ensure they are displayed
            return `ERROR: ${message.data.error}`;
        default:
            // Exhaustive check fallback
            // If WSMessage is extended, this helps catch unhandled types during development.
            console.warn("Unrecognized message type encountered:", message);
            return "[Unrecognized message format]";
    }
};