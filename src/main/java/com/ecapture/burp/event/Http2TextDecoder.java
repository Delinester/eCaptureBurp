package com.ecapture.burp.event;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * Consumes eCapture v2.6.0 HTTP2Request/Response.Display(), not binary HTTP/2.
 * Produces HTTP/1.1-style editor views while retaining stream identity.
 * No invented headers when upstream reports an HPACK/CONTINUATION failure.
 */
final class Http2TextDecoder {
    private static final Pattern FRAME = Pattern.compile(
            "\\nFrame Type\\t=>\\t([^\\n]+)\\nFrame StreamID\\t=>\\t(\\d+)\\n(?:Frame Length\\t=>\\t(\\d+)\\n)?"
            + "|\\nMerged Data Frame, StreamID\\t=>\\t(\\d+)\\nMerged Data Frame, Final Length\\t=>\\t(\\d+)\\n\\n");
    private static final Pattern HEADER = Pattern.compile(
            "header field \"((?:\\\\.|[^\"\\\\])*)\" = \"((?:\\\\.|[^\"\\\\])*)\"(?: \\(sensitive\\))?");
    private static final int MAX_BODY = 8 * 1024 * 1024;
    private final LinkedHashMap<String, Stream> streams = new LinkedHashMap<>();
    private String warning = "";
    private static final class Stream {
        final List<String[]> headers = new ArrayList<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        long touched = System.currentTimeMillis();
        boolean decompressed;
        String field(String name) {
            return headers.stream().filter(h -> h[0].equals(name))
                    .map(h -> h[1]).findFirst().orElse("");
        }
    }
    boolean accepts(CapturedEvent e) {
        return FRAME.matcher(new String(e.getPayload(), StandardCharsets.ISO_8859_1)).find();
    }
    void clear() { streams.clear(); }
    String warning() { return warning; }

    List<CapturedEvent> decode(CapturedEvent event) {
        warning = "";
        long now = System.currentTimeMillis();
        streams.entrySet().removeIf(e -> now - e.getValue().touched > 300_000);
        String text = new String(event.getPayload(), StandardCharsets.ISO_8859_1);
        LinkedHashMap<Integer, Stream> changed = new LinkedHashMap<>();
        Matcher frame = FRAME.matcher(text);
        int offset = 0;
        while (frame.find(offset)) {
            boolean merged = frame.group(4) != null;
            int id = Integer.parseInt(merged ? frame.group(4) : frame.group(2));
            String kind = merged ? "MERGED" : frame.group(1);
            int end = frame.end();
            offset = end;
            if (id == 0) continue;
            String connection = event.connectionKey();
            // Without a connection identity, don't merge unrelated captures.
            if (connection.isEmpty()) connection = "isolated:" + System.identityHashCode(event);
            String key = connection + "|" + event.getWireType() + "|" + id;
            Stream stream = streams.computeIfAbsent(key, k -> new Stream());
            stream.touched = now;
            if ("HEADERS".equals(kind)) {
                Matcher header = HEADER.matcher(text);
                header.region(end, text.length());
                while (header.lookingAt()) {
                    stream.headers.add(new String[]{unquote(header.group(1)), unquote(header.group(2))});
                    offset = header.end();
                    if (offset < text.length() && text.charAt(offset) == '\n') offset++;
                    header.region(offset, text.length());
                }
                changed.put(id, stream);
            } else if ("DATA".equals(kind) || merged) {
                int length = Integer.parseInt(merged ? frame.group(5) : frame.group(3));
                if (text.startsWith("Partial entity body with gzip encoding", end)) continue;
                // Length-based consumption prevents body text looking like a
                // frame marker from being mistaken for a second request.
                if (length < 0 || length > text.length() - end
                        || length + stream.body.size() > MAX_BODY) {
                    warning = "Incomplete or oversized HTTP/2 DATA dump; available headers retained";
                    break;
                }
                if (merged) { stream.body.reset(); stream.decompressed = true; }
                stream.body.writeBytes(text.substring(end, end + length).getBytes(StandardCharsets.ISO_8859_1));
                offset = end + length;
                changed.put(id, stream);
            }
            while (streams.size() > 512) streams.remove(streams.keySet().iterator().next());
        }
        List<CapturedEvent> result = new ArrayList<>();
        changed.forEach((id, stream) -> {
            String method = stream.field(":method"), status = stream.field(":status");
            if (method.isEmpty() && status.isEmpty()) return;
            boolean request = !method.isEmpty();
            String path = stream.field(":path");
            if (path.isEmpty() && "CONNECT".equals(method)) path = stream.field(":authority");
            if (request && path.isEmpty()) path = "(path-unavailable)";
            StringBuilder http = new StringBuilder(request
                    ? method + " " + path + " HTTP/1.1\r\n"
                    : "HTTP/1.1 " + status + "\r\n");
            if (request && !stream.field(":authority").isEmpty())
                http.append("Host: ").append(stream.field(":authority")).append("\r\n");
            for (String[] header : stream.headers) {
                if (header[0].startsWith(":") || header[0].equals("content-length")
                        || header[0].equals("transfer-encoding")
                        || (stream.decompressed && header[0].equals("content-encoding"))) continue;
                http.append(header[0]).append(": ").append(header[1]).append("\r\n");
            }
            http.append("Content-Length: ").append(stream.body.size()).append("\r\n\r\n");
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.writeBytes(http.toString().getBytes(StandardCharsets.ISO_8859_1));
            output.writeBytes(stream.body.toByteArray());
            result.add(event.normalized(output.toByteArray(), request ? 2 : 4, id, stream.field(":scheme")));
        });
        return result;
    }

    /** Go hpack.HeaderField.String uses %q (Go quoted-string escapes). */
    static String unquote(String value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\') { output.write(c); continue; }
            if (++i >= value.length()) throw new IllegalArgumentException("Truncated Go escape");
            c = value.charAt(i);
            String escapes = "abfnrtv";
            int pos = escapes.indexOf(c);
            if (pos >= 0) { output.write(new int[]{7,8,12,10,13,9,11}[pos]); continue; }
            int digits = c == 'x' ? 2 : c == 'u' ? 4 : c == 'U' ? 8 : 0;
            if (digits > 0) {
                int code = Integer.parseUnsignedInt(value.substring(i + 1, i + 1 + digits), 16);
                if (c == 'x') output.write(code);
                else output.writeBytes(new String(Character.toChars(code)).getBytes(StandardCharsets.UTF_8));
                i += digits;
            } else if (c >= '0' && c <= '7') {
                output.write(Integer.parseInt(value.substring(i, i + 3), 8)); i += 2;
            } else output.write(c);
        }
        return output.toString(StandardCharsets.ISO_8859_1);
    }
}
