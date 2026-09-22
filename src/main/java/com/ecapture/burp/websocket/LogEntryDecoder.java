package com.ecapture.burp.websocket;

import com.ecapture.burp.proto.Event;
import com.ecapture.burp.proto.LogEntry;
import com.ecapture.burp.proto.LogType;
import com.google.protobuf.InvalidProtocolBufferException;

/** Handles both ordinary LogEntry frames and v2.6.0's WriteEvent envelope. */
public final class LogEntryDecoder {
    private LogEntryDecoder() {}

    public static LogEntry decode(byte[] bytes) throws InvalidProtocolBufferException {
        LogEntry entry = LogEntry.parseFrom(bytes);
        for (int depth = 0; depth < 4; depth++) {
            if (entry.getLogType() != LogType.LOG_TYPE_EVENT || !entry.hasEventPayload()) break;
            Event event = entry.getEventPayload();
            // WriteEvent populates ONLY length and payload. Never interpret a
            // real, metadata-bearing event's HTTP body as another envelope.
            if (event.getType() != 0 || !event.getUuid().isEmpty() || event.getPid() != 0
                    || event.getTimestamp() != 0 || !event.getPname().isEmpty()
                    || !event.getSrcIp().isEmpty() || !event.getDstIp().isEmpty()
                    || event.getSrcPort() != 0 || event.getDstPort() != 0
                    || event.getPayload().isEmpty()
                    || event.getLength() != event.getPayload().size()) break;
            try {
                LogEntry inner = LogEntry.parseFrom(event.getPayload());
                if (inner.getLogType() != LogType.LOG_TYPE_EVENT || !inner.hasEventPayload()
                        || inner.getEventPayload().getPayload().isEmpty()) break;
                entry = inner;
            } catch (InvalidProtocolBufferException notAnEnvelope) {
                break; // Plain HTTP/raw payloads are valid in a single envelope.
            }
        }
        return entry;
    }
}
