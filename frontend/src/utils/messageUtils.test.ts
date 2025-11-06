// src/utils/messageUtils.test.ts
import { describe, it, expect } from 'vitest';
import { getMessageContent } from './messageUtils';
import { ChatEntry, MessageType, SenderType } from '../types';

// 4. Add a Testing Strategy: Unit tests for the message utility

describe('getMessageContent', () => {
  const baseEntry: Omit<ChatEntry, 'message'> = {
    id: '1',
    sender: SenderType.System,
  };

  it('should return the prompt for UserPrompt', () => {
    const entry: ChatEntry = {
        ...baseEntry,
        sender: SenderType.User,
        message: {
            type: MessageType.UserPrompt,
            data: { prompt: 'Hello world' },
            timestamp: '',
            request_id: '1',
        },
    };
    expect(getMessageContent(entry)).toBe('Hello world');
  });

  // Test for Point 1
  it('should format the error for SystemError', () => {
    const entry: ChatEntry = {
        ...baseEntry,
        message: {
            type: MessageType.SystemError,
            data: { error: 'Invalid input' },
            timestamp: '',
        },
    };
    expect(getMessageContent(entry)).toBe('ERROR: Invalid input');
  });

  // Test for Point 3: Ensure content is returned even if failed
  it('should return the original prompt if delivery status is Failed', () => {
    const entry: ChatEntry = {
        ...baseEntry,
        sender: SenderType.User,
        status: 'failed',
        error: 'Timeout',
        message: {
            type: MessageType.UserPrompt,
            data: { prompt: 'My command' },
            timestamp: '',
            request_id: '1',
        },
    };
    expect(getMessageContent(entry)).toBe('My command');
  });
});