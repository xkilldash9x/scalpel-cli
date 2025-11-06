// src/components/ChatInput.test.tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ChatInput } from './ChatInput';
import { useWebSocketState, useWebSocketActions } from '../context/WebSocketContext';
import { ConnectionStatus } from '../types';

// 4. Add a Testing Strategy: Mock the context hooks used by ChatInput
vi.mock('../context/WebSocketContext', async (importOriginal)=>{
  const actual = await importOriginal<typeof import('../context/WebSocketContext')>();
  return {
    ...actual,
    useWebSocketState: vi.fn(),
    useWebSocketActions: vi.fn(),
  };
});

const mockSendPrompt = vi.fn();
// Helper function to render the component with mocked context state
const setup = (status: ConnectionStatus) => {
   (useWebSocketState as ReturnType<typeof vi.fn>).mockReturnValue({ status });
   (useWebSocketActions as ReturnType<typeof vi.fn>).mockReturnValue({ sendPrompt: mockSendPrompt });
   render(<ChatInput />);
};

describe('ChatInput Integration Tests', () => {
   beforeEach(() => {
     vi.clearAllMocks();
   });

   // Test suggested in Point 4: "does the button disable when disconnected?"
   it('should be disabled when disconnected (CLOSED)', () => {
     setup('CLOSED');
     const textarea = screen.getByRole('textbox', { name: /command input/i });
     const button = screen.getByRole('button', { name: /execute/i });

     expect(textarea).toBeDisabled();
     expect(button).toBeDisabled();
     expect(textarea).toHaveAttribute('placeholder', '// Awaiting connection...');
   });

   it('should be enabled when connected (OPEN), but button disabled if empty', () => {
     setup('OPEN');
     const textarea = screen.getByRole('textbox');
     const button = screen.getByRole('button');

     expect(textarea).toBeEnabled();
    // The button should be disabled when the input is empty
     expect(button).toBeDisabled();
     expect(textarea).toHaveAttribute('placeholder', '// Enter command or prompt...');
   });

   it('should call sendPrompt and clear input on submit', async () => {
     setup('OPEN');
     const textarea = screen.getByRole('textbox');
    const button = screen.getByRole('button');

     // Wrap user events that cause state updates in act()
     await act(async () => {
       await userEvent.type(textarea, 'execute command');
      // After typing, the button should be enabled
       await userEvent.click(button);
     });

     expect(mockSendPrompt).toHaveBeenCalledTimes(1);
     expect(mockSendPrompt).toHaveBeenCalledWith('execute command');
    // After submit, the textarea value should be cleared
     expect(textarea).toHaveValue('');
   });

   it('should handle submission via Enter key (without Shift)', async () => {
     setup('OPEN');
     const textarea = screen.getByRole('textbox');

     // Wrap user event that causes state update in act()
     await act(async () => {
       await userEvent.type(textarea, 'quick command{enter}');
     });

     expect(mockSendPrompt).toHaveBeenCalledWith('quick command');
   });
});