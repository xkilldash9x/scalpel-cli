export var MessageType;
(function (MessageType) {
    MessageType["AgentResponse"] = "AGENT_RESPONSE";
    MessageType["StatusUpdate"] = "STATUS_UPDATE";
    MessageType["UserPrompt"] = "USER_PROMPT";
    MessageType["SystemError"] = "SYSTEM_ERROR";
})(MessageType || (MessageType = {}));
export var SenderType;
(function (SenderType) {
    SenderType["User"] = "user";
    SenderType["Agent"] = "agent";
    SenderType["System"] = "system";
})(SenderType || (SenderType = {}));
