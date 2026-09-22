package com.ecapture.burp.event;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.*;

/** v2.6.0 collector and direct OpenSSL text output envelope formats. */
public final class CollectorEventDecoder {
    private static final Pattern PREFIX = Pattern.compile(
            "^PID:(\\d+), Comm:(.*), Src:(.*):(\\d+), Dest:(.*):(\\d+),\\r?\\n");
    private static final Pattern OPENSSL = Pattern.compile(
            "^\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?)\\]"
            + "[ \\t]+PID:(\\d+)[ \\t]+TID:(\\d+)[ \\t]+Comm:([^\\r\\n]*?)"
            + "[ \\t]+FD:(\\d+)[ \\t]+(READ|WRITE)[ \\t]+\\((\\d+) bytes\\):\\r?\\n");
    private static final Pattern CONNECTION = Pattern.compile(
            "^PID:\\d+, Comm:[^\\r\\n]*, TID:\\d+, FD:\\d+, Tuple:[^\\r\\n]*(?:\\r?\\n)?$");
    private CollectorEventDecoder() {}
    public static boolean isConnectionMetadata(CapturedEvent source) {
        return CONNECTION.matcher(new String(source.getPayload(), StandardCharsets.ISO_8859_1)).matches();
    }
    public static CapturedEvent decode(CapturedEvent source) {
        byte[] bytes = source.getPayload();
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        Matcher direct = OPENSSL.matcher(text);
        if (direct.find()) {
            int end = bytes.length;
            long declared = Long.parseLong(direct.group(7));
            // TextHandler appends one LF when String() does not end in LF.
            // Strip ONLY that exact extra byte. Never trim() HTTP or binary data.
            if (end - direct.end() == declared + 1 && bytes[end - 1] == '\n') end--;
            byte[] http = Arrays.copyOfRange(bytes, direct.end(), end);
            String uuid = source.getUuid();
            // FD=0 is ambiguous in the observed output. Do not cross-pair
            // unrelated requests based only on PID/TID or an unknown descriptor.
            if (uuid.isEmpty() && Long.parseLong(direct.group(5)) > 0)
                uuid = "openssl:" + direct.group(2) + ":fd:" + direct.group(5);
            CapturedEvent result = new CapturedEvent(source.getTimestamp(), uuid,
                    source.getSrcIp(), source.getSrcPort(), source.getDstIp(), source.getDstPort(),
                    Long.parseLong(direct.group(2)), direct.group(4).trim(),
                    http2Type(new String(http, StandardCharsets.ISO_8859_1)), http.length, http);
            result.retainOriginal(source.getRawPayload());
            result.setCaptureTime(direct.group(1));
            return result;
        }
        Matcher prefix = PREFIX.matcher(text);
        if (!prefix.find()) return source;
        byte[] http = Arrays.copyOfRange(bytes, prefix.end(), bytes.length);
        String dump = text.substring(prefix.end());
        int type = http2Type(dump);
        CapturedEvent result = new CapturedEvent(source.getTimestamp(), source.getUuid(),
                prefix.group(3), Integer.parseInt(prefix.group(4)),
                prefix.group(5), Integer.parseInt(prefix.group(6)),
                Long.parseLong(prefix.group(1)), prefix.group(2), type, http.length, http);
        result.retainOriginal(source.getRawPayload());
        return result;
    }

    private static int http2Type(String dump) {
        return dump.contains("header field \":method\" = ") ? 2
                : dump.contains("header field \":status\" = ") ? 4 : 0;
    }
}
