export type ConnectionStatus = 'CONNECTING' | 'OPEN' | 'CLOSED' | 'ERROR';

export enum MessageType {
  AgentResponse = 'AGENT_RESPONSE',
  StatusUpdate = 'STATUS_UPDATE',
  UserPrompt = 'USER_PROMPT',
  SystemError = 'SYSTEM_ERROR',
}

interface BaseMessage {
  timestamp: string;
  request_id?: string;
}

// Discriminated Unions for strict typing and robustness
export interface AgentResponseMessage extends BaseMessage {
  type: MessageType.AgentResponse;
  data: { message: string; };
}

export interface UserPromptMessage extends BaseMessage {
    type: MessageType.UserPrompt;
    data: { prompt: string; };
    request_id: string; // Required for user prompts
}

export interface StatusUpdateMessage extends BaseMessage {
  type: MessageType.StatusUpdate;
  data: { status: string; };
}

export interface SystemErrorMessage extends BaseMessage {
    type: MessageType.SystemError;
    data: { error: string; };
}

export type WSMessage = AgentResponseMessage | StatusUpdateMessage | UserPromptMessage | SystemErrorMessage;

export enum SenderType {
    User = 'user',
    Agent = 'agent',
    System = 'system',
}


// 3. Enhance Optimistic UI: Define delivery status
export type DeliveryStatus = 'sending' | 'sent' | 'failed';

export interface ChatEntry {
  id: string;
  message: WSMessage;
  sender: SenderType;
// Enhance Optimistic UI: Track status and errors
status?: DeliveryStatus;
error?: string;
}