package com.ecapture.burp.event;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Bytes received from eCapture, or an explicitly normalized HTTP/2 view. */
public class CapturedEvent {
    public enum EventType {
        UNKNOWN(0, "Unknown"), HTTP1_REQUEST(1, "HTTP/1.x Request"),
        HTTP2_REQUEST(2, "HTTP/2 Request"), HTTP1_RESPONSE(3, "HTTP/1.x Response"),
        HTTP2_RESPONSE(4, "HTTP/2 Response"), AUTO_REQUEST(-1, "Detected request"),
        AUTO_RESPONSE(-2, "Detected response");
        private final int code;
        private final String description;
        EventType(int code, String description) { this.code = code; this.description = description; }
        public int getCode() { return code; }
        public String getDescription() { return description; }
        public static EventType fromCode(int code) {
            for (EventType type : values()) if (type.code == code) return type;
            return UNKNOWN;
        }
        public boolean isRequest() {
            return this == HTTP1_REQUEST || this == HTTP2_REQUEST || this == AUTO_REQUEST;
        }
        public boolean isResponse() {
            return this == HTTP1_RESPONSE || this == HTTP2_RESPONSE || this == AUTO_RESPONSE;
        }
    }

    private static final Pattern REQUEST = Pattern.compile(
            "^([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^\\r\\n ]+) HTTP/\\d(?:\\.\\d)?(?:\\r?\\n|$)");
    private static final Pattern RESPONSE = Pattern.compile("^HTTP/\\d(?:\\.\\d)? ([0-9]{3})(?:[ \\r\\n]|$)");
    private static final Pattern UUID = Pattern.compile(
            "^(?:sock:)?(\\d+)_\\d+_(.+)_(\\d+)_[01](?:_([^_]+)(?:_(\\d+))?)?$");
    private final long timestamp, pid, receivedAt;
    private final String uuid, srcIp, dstIp, processName;
    private final int srcPort, dstPort, wireType;
    private final EventType eventType;
    private final byte[] payload;
    private int streamId;
    private byte[] rawPayload;
    private String scheme = "";
    private String captureTime = "";

    public CapturedEvent(long timestamp, String uuid, String srcIp, int srcPort,
                         String dstIp, int dstPort, long pid, String processName,
                         int type, int length, byte[] payload) {
        this.timestamp = timestamp;
        this.uuid = uuid == null ? "" : uuid;
        this.srcIp = srcIp == null ? "" : srcIp;
        this.dstIp = dstIp == null ? "" : dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.pid = pid;
        this.processName = processName == null ? "" : processName;
        this.wireType = type;
        this.payload = payload == null ? new byte[0] : payload.clone();
        this.rawPayload = this.payload;
        this.receivedAt = System.currentTimeMillis();
        EventType detected = EventType.fromCode(type);
        String text = text();
        // Content wins over misleading/missing metadata, but don't treat the
        // HTTP/2 connection preface as an application request.
        if (RESPONSE.matcher(text).find()) detected = EventType.AUTO_RESPONSE;
        else if (REQUEST.matcher(text).find() && !text.startsWith("PRI * HTTP/2.0"))
            detected = EventType.AUTO_REQUEST;
        this.eventType = detected;
    }

    public CapturedEvent normalized(byte[] http, int type, int stream, String scheme) {
        CapturedEvent result = new CapturedEvent(timestamp, uuid, srcIp, srcPort,
                dstIp, dstPort, pid, processName, type, http.length, http);
        result.streamId = stream;
        result.scheme = scheme;
        result.rawPayload = rawPayload;
        result.captureTime = captureTime;
        return result;
    }

    private String text() { return new String(payload, StandardCharsets.ISO_8859_1); }
    public String getHttpMethod() {
        Matcher m = REQUEST.matcher(text());
        return m.find() ? m.group(1) : "-";
    }
    public String getUrl() {
        Matcher m = REQUEST.matcher(text());
        return m.find() ? m.group(2) : "-";
    }
    public String getStatusCode() {
        Matcher m = RESPONSE.matcher(text());
        return m.find() ? m.group(1) : "-";
    }
    public String getHost() {
        String headers = text().split("\\r?\\n\\r?\\n", 2)[0];
        Matcher host = Pattern.compile("(?im)^host\\s*:[ \\t]*([^\\r\\n]+)").matcher(headers);
        if (host.find()) return host.group(1).trim();
        String target = getUrl();
        if (target.startsWith("http://") || target.startsWith("https://")) {
            try { return java.net.URI.create(target).getRawAuthority(); }
            catch (IllegalArgumentException ignored) {}
        }
        if ("CONNECT".equals(getHttpMethod())) return target;
        return dstIp.isEmpty() || "0.0.0.0".equals(dstIp) ? "(unknown)" : dstIp;
    }
    public String connectionKey() {
        if (!srcIp.isEmpty() && !dstIp.isEmpty() && srcPort > 0 && dstPort > 0) {
            String a = getSource(), b = getDestination();
            return pid + "|" + (a.compareTo(b) <= 0 ? a + "|" + b : b + "|" + a);
        }
        Matcher m = UUID.matcher(uuid);
        if (m.matches()) {
            return m.group(1) + "|" + m.group(2) + "|fd:" + m.group(3)
                    + "|tuple:" + m.group(4) + "|sock:" + m.group(5);
        }
        // Never group all metadata-less traffic under a shared "unknown".
        return uuid.isEmpty() ? "" : pid + "|" + uuid;
    }
    public String getFormattedTimestamp() {
        if (!captureTime.isEmpty()) return captureTime;
        long seconds = timestamp;
        if (seconds > 100_000_000_000_000_000L) seconds /= 1_000_000_000L;
        else if (seconds > 100_000_000_000_000L) seconds /= 1_000_000L;
        else if (seconds > 100_000_000_000L) seconds /= 1000L;
        // Probe timestamps can be monotonic rather than Unix time.
        if (seconds < 946684800L || seconds > 4102444800L) seconds = receivedAt / 1000L;
        return Instant.ofEpochSecond(seconds).atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
    public long getTimestamp() { return timestamp; }
    public String getUuid() { return uuid; }
    public String getSrcIp() { return srcIp; }
    public int getSrcPort() { return srcPort; }
    public String getDstIp() { return dstIp; }
    public int getDstPort() { return dstPort; }
    public String getSource() { return srcIp + ":" + srcPort; }
    public String getDestination() { return dstIp + ":" + dstPort; }
    public long getPid() { return pid; }
    public String getProcessName() { return processName; }
    public EventType getEventType() { return eventType; }
    public int getWireType() { return wireType; }
    public int getLength() { return payload.length; }
    public byte[] getPayload() { return payload; }
    public byte[] getRawPayload() { return rawPayload; }
    void retainOriginal(byte[] bytes) { rawPayload = bytes; }
    void setCaptureTime(String value) { captureTime = value; }
    public int getStreamId() { return streamId; }
    public String getScheme() { return scheme; }
    public long getReceivedAt() { return receivedAt; }
    public boolean isRequest() { return eventType.isRequest(); }
    public boolean isResponse() { return eventType.isResponse(); }
    @Override public String toString() {
        return "uuid=" + uuid + " type=" + wireType + " stream=" + streamId
                + " process=" + processName + "(" + pid + ") bytes=" + payload.length;
    }
}
