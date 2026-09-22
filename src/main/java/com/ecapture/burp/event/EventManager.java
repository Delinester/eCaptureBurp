package com.ecapture.burp.event;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/** Separates received transport events from visible HTTP messages. */
public class EventManager {
    private final MontoyaApi api;
    private final Logging logging;
    private final List<MatchedHttpPair> matchedPairs = new ArrayList<>();
    private final Map<String, Deque<MatchedHttpPair>> pending = new HashMap<>();
    private final LinkedHashMap<String, MatchedHttpPair> h2Pairs = new LinkedHashMap<>();
    private final List<String> runtimeLogs = new ArrayList<>();
    private final List<Consumer<MatchedHttpPair>> pairListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
    private final Http2TextDecoder h2 = new Http2TextDecoder();
    private volatile long totalEventsReceived, lastHeartbeatTime, heartbeatCount, unparsedEvents, metadataEvents, generation;
    private long sequence;

    public EventManager(MontoyaApi api) { this.api = api; this.logging = api.logging(); }

    public synchronized void processEvent(CapturedEvent event) {
        totalEventsReceived++;
        if (CollectorEventDecoder.isConnectionMetadata(event)) {
            metadataEvents++;
            return;
        }
        try { event = CollectorEventDecoder.decode(event); }
        catch (RuntimeException error) {
            unparsed(event, "Invalid collector prefix: " + error.getMessage());
            return;
        }
        cleanup();
        if (h2.accepts(event)) {
            try {
                List<CapturedEvent> decoded = h2.decode(event);
                for (CapturedEvent message : decoded) processHttp(message);
                if (!h2.warning().isEmpty()) unparsed(event, h2.warning());
                else if (decoded.isEmpty()) unparsed(event, "HTTP/2 control/data-only frame or headers unavailable");
                else if (new String(event.getPayload(), java.nio.charset.StandardCharsets.ISO_8859_1)
                        .contains("Incorrect HPACK context"))
                    unparsed(event, "Upstream HTTP/2 HPACK context is incomplete; partial headers shown");
            } catch (RuntimeException error) {
                unparsed(event, "HTTP/2 dump parse error: " + error.getMessage());
            }
        } else if (event.isRequest() || event.isResponse()) {
            // Show even incomplete typed HTTP events: missing Host/path is
            // not a reason to discard captured traffic.
            processHttp(event);
        } else {
            unparsed(event, "Not recognized as a complete HTTP message");
        }
    }

    private void processHttp(CapturedEvent event) {
        String connection = event.connectionKey();
        String streamKey = connection + "|stream:" + event.getStreamId();
        MatchedHttpPair pair = null;
        if (event.getStreamId() > 0 && !connection.isEmpty()) {
            pair = h2Pairs.get(streamKey);
            if (pair == null) {
                pair = newPair();
                h2Pairs.put(streamKey, pair);
            }
        } else if (event.isRequest()) {
            pair = newPair();
            if (!connection.isEmpty()) pending.computeIfAbsent(connection, k -> new ArrayDeque<>()).add(pair);
        } else if (!connection.isEmpty()) {
            Deque<MatchedHttpPair> queue = pending.get(connection);
            if (queue != null && !queue.isEmpty()) {
                pair = queue.peek();
                int status = 0;
                try { status = Integer.parseInt(event.getStatusCode()); } catch (NumberFormatException ignored) {}
                // Informational responses must not consume the request.
                if (status >= 200 || status == 101) queue.remove();
            }
        }
        if (pair == null) pair = newPair(); // Standalone response stays visible.
        if (event.isRequest()) pair.setRequest(event); else pair.setResponse(event);
        notifyPair(pair);
        if (pair.isComplete()) sendToSiteMapSafe(pair);
    }

    private MatchedHttpPair newPair() {
        MatchedHttpPair pair = new MatchedHttpPair("capture-" + ++sequence);
        matchedPairs.add(pair);
        return pair;
    }
    private void cleanup() {
        long cutoff = System.currentTimeMillis() - 300_000;
        pending.values().forEach(q -> q.removeIf(p -> p.getCreatedAt() < cutoff));
        pending.entrySet().removeIf(e -> e.getValue().isEmpty());
        h2Pairs.entrySet().removeIf(e -> e.getValue().getCreatedAt() < cutoff);
        while (h2Pairs.size() > 512) h2Pairs.remove(h2Pairs.keySet().iterator().next());
    }
    private void unparsed(CapturedEvent event, String reason) {
        unparsedEvents++;
        byte[] bytes = event.getPayload();
        int size = Math.min(bytes.length, 2048);
        String text = new String(bytes, 0, size, java.nio.charset.StandardCharsets.ISO_8859_1);
        processRuntimeLog(reason + "; " + event + "\n"
                + text.replace("\u0000", "\\0") + (size < bytes.length ? "\n[preview truncated]" : ""));
    }
    private void notifyPair(MatchedHttpPair pair) {
        for (Consumer<MatchedHttpPair> listener : pairListeners) {
            try { listener.accept(pair); }
            catch (RuntimeException e) { logging.logToError("Pair listener failed: " + e.getMessage()); }
        }
    }
    private void sendToSiteMapSafe(MatchedHttpPair pair) {
        try {
            String host = pair.getHost();
            if (host.equals("(unknown)") || host.isBlank()) return;
            HttpService service = HttpService.httpService(pair.getServiceHost(), pair.getPort(), pair.isHttps());
            HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(pair.getRequest().getPayload()));
            HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(pair.getResponse().getPayload()));
            api.siteMap().add(HttpRequestResponse.httpRequestResponse(request, response));
        } catch (RuntimeException e) {
            logging.logToError("Optional Site Map update failed: " + e.getMessage());
        }
    }
    public void processHeartbeat(long timestamp, long count, String message) {
        lastHeartbeatTime = System.currentTimeMillis(); heartbeatCount = count;
    }
    public synchronized void processRuntimeLog(String message) {
        runtimeLogs.add(message);
        if (runtimeLogs.size() > 1000) runtimeLogs.remove(0);
        for (Consumer<String> listener : logListeners) {
            try { listener.accept(message); }
            catch (RuntimeException e) { logging.logToError("Log listener failed: " + e.getMessage()); }
        }
    }
    public void addPairListener(Consumer<MatchedHttpPair> listener) { pairListeners.add(listener); }
    public void addLogListener(Consumer<String> listener) { logListeners.add(listener); }
    public synchronized List<MatchedHttpPair> getMatchedPairs() { return new ArrayList<>(matchedPairs); }
    public synchronized List<String> getRuntimeLogs() { return new ArrayList<>(runtimeLogs); }
    public synchronized void clear() {
        generation++;
        matchedPairs.clear(); pending.clear(); h2Pairs.clear(); h2.clear(); runtimeLogs.clear();
        totalEventsReceived = 0; unparsedEvents = 0; metadataEvents = 0;
    }
    public long getGeneration() { return generation; }
    public long getTotalEventsReceived() { return totalEventsReceived; }
    public synchronized long getTotalPairsMatched() {
        return matchedPairs.stream().filter(MatchedHttpPair::hasRequest).count();
    }
    public long getUnparsedEvents() { return unparsedEvents; }
    public long getMetadataEvents() { return metadataEvents; }
    public long getLastHeartbeatTime() { return lastHeartbeatTime; }
    public long getHeartbeatCount() { return heartbeatCount; }
    public synchronized int getPendingPairsCount() {
        return (int) matchedPairs.stream().filter(p -> p.hasRequest() && !p.hasResponse()).count();
    }
}
