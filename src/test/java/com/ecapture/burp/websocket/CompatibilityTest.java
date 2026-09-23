package com.ecapture.burp.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.ecapture.burp.event.*;
import com.ecapture.burp.proto.*;
import com.ecapture.burp.ui.ECaptureTab;
import com.google.protobuf.ByteString;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import javax.swing.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

class CompatibilityTest {
    MontoyaApi api;
    EventManager manager;
    ECaptureWebSocketClient client;
    @BeforeEach void setup() {
        api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        var logging = api.logging();
        doAnswer(call -> { System.err.println("BURP LOG: " + call.getArgument(0)); return null; })
                .when(logging).logToError(anyString());
        manager = new EventManager(api);
        client = new ECaptureWebSocketClient(api, manager);
    }
    @AfterEach void cleanup() { client.shutdown(); manager.shutdown(); }
    static byte[] fixture(String name) throws Exception {
        return resource(name + ".bin");
    }
    static byte[] resource(String name) throws Exception {
        try (var input = CompatibilityTest.class.getResourceAsStream("/ecapture260/" + name)) {
            assertNotNull(input, name); return input.readAllBytes();
        }
    }
    void feed(byte[] bytes) { client.handleBinaryMessage(ByteBuffer.wrap(bytes)); }
    void feed(String name) throws Exception { feed(fixture(name)); }
    CapturedEvent event(String uuid, int type, String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.ISO_8859_1);
        return new CapturedEvent(1780000000000000000L, uuid, "", 0, "", 0,
                4242, "fixture_client", type, bytes.length, bytes);
    }
    @Test void real260CollectorFixtureExplainsOldFailureAndIsDisplayedNow() throws Exception {
        Event outer = LogEntry.parseFrom(fixture("http1-get")).getEventPayload();
        assertEquals(0, outer.getType());
        assertTrue(outer.getUuid().isEmpty());
        assertTrue(outer.getPayload().toStringUtf8().startsWith("PID:4242, Comm:"));
        assertFalse(outer.getPayload().toStringUtf8().startsWith("GET "));
        feed("http1-get");
        assertEquals(1, manager.getTotalEventsReceived());
        var request = manager.getMatchedPairs().get(0).getRequest();
        assertEquals("GET", request.getHttpMethod());
        assertEquals("/from-ecapture-260", request.getUrl());
        assertEquals("example.test", request.getHost());
        assertEquals(4242, request.getPid());
        assertEquals("fixture_client", request.getProcessName());
        assertEquals(0, manager.getUnparsedEvents());
    }
    @Test void real260PatchPreservesBinaryBody() throws Exception {
        feed("http1-patch");
        byte[] payload = manager.getMatchedPairs().get(0).getRequest().getPayload();
        assertEquals("PATCH", manager.getMatchedPairs().get(0).getMethod());
        assertArrayEquals(new byte[]{0, (byte)255, (byte)128, 65},
                Arrays.copyOfRange(payload, payload.length - 4, payload.length));
    }
    @Test void real260Http2ProducesTwoRequestsNotFrameTextAsMethod() throws Exception {
        feed("http2-multiplex");
        var pairs = manager.getMatchedPairs();
        assertEquals(2, pairs.size());
        assertEquals(List.of("/stream/1", "/stream/3"), pairs.stream().map(MatchedHttpPair::getUrl).toList());
        for (var pair : pairs) {
            assertEquals("GET", pair.getMethod());
            assertEquals("h2.example.test", pair.getHost());
            assertTrue(new String(pair.getRequest().getPayload(), StandardCharsets.ISO_8859_1)
                    .startsWith("GET /stream/"));
        }
    }
    @Test void real260NestedEnvelopeIsSupportedToo() throws Exception {
        feed("nested");
        assertEquals("DELETE", manager.getMatchedPairs().get(0).getMethod());
        assertEquals("/nested", manager.getMatchedPairs().get(0).getUrl());
    }
    @Test void real260Http2PostPreservesBinaryData() throws Exception {
        feed("http2-post");
        var pair = manager.getMatchedPairs().get(0);
        assertEquals("POST", pair.getMethod());
        assertEquals("/binary", pair.getUrl());
        byte[] payload = pair.getRequest().getPayload();
        assertArrayEquals(new byte[]{0,(byte)255,(byte)128,65},
                Arrays.copyOfRange(payload, payload.length - 4, payload.length));
    }
    @Test void real260Http2GzipResponseHasCorrectNormalizedEncoding() throws Exception {
        feed("http2-gzip-response");
        var pair = manager.getMatchedPairs().get(0);
        assertEquals("200", pair.getStatusCode());
        String http = new String(pair.getResponse().getPayload(), StandardCharsets.ISO_8859_1);
        assertTrue(http.endsWith("\r\n\r\ndecompressed-body"));
        assertFalse(http.contains("content-encoding: gzip"));
    }
    @Test void incompleteHttp2BodyDoesNotHideItsRequestHeaders() {
        manager.processEvent(event("4242_1_app_7_1", 2,
                headers(1, "header field \":method\" = \"POST\"\nheader field \":path\" = \"/partial\"\n")
                + "\nFrame Type\t=>\tDATA\nFrame StreamID\t=>\t1\nFrame Length\t=>\t100\nshort\n"));
        assertEquals("/partial", manager.getMatchedPairs().get(0).getUrl());
        assertEquals(1, manager.getUnparsedEvents());
    }
    @Test void singleEnvelopeAndOrdinaryBodyAreNotOverDecoded() {
        Event event = Event.newBuilder().setType(1).setUuid("id")
                .setPayload(ByteString.copyFromUtf8("PUT /plain HTTP/1.1\r\nHost: example.test\r\n\r\n")).build();
        feed(LogEntry.newBuilder().setLogType(LogType.LOG_TYPE_EVENT).setEventPayload(event).build().toByteArray());
        assertEquals("PUT", manager.getMatchedPairs().get(0).getMethod());
    }
    @ParameterizedTest @ValueSource(strings = {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE","CONNECT","PROPFIND","CUSTOM-METHOD"})
    void allHttpMethodsAreVisibleWithoutAHostOrResponse(String method) {
        manager.processEvent(event("", 0, method + " /target HTTP/1.0\r\n\r\n"));
        assertEquals(1, manager.getMatchedPairs().size());
        assertEquals(method, manager.getMatchedPairs().get(0).getMethod());
        assertEquals(1, manager.getPendingPairsCount());
    }
    @Test void caseInsensitiveHostAndNoBodyHeaderFalsePositive() {
        assertEquals("MiXeD.test:8443", event("", 0,
                "GET / HTTP/1.1\r\nhOsT: MiXeD.test:8443\r\n\r\n").getHost());
        assertEquals("(unknown)", event("", 0,
                "POST / HTTP/1.0\r\n\r\nHost: body-not-a-header\r\n").getHost());
    }
    @Test void rapidEventsNeverReuseRowIdentifiers() {
        for (int i = 0; i < 100; i++)
            manager.processEvent(event("4242_1_app_7_1", 1, "GET /" + i + " HTTP/1.1\r\n\r\n"));
        assertEquals(100, manager.getMatchedPairs().stream().map(MatchedHttpPair::getUuid).distinct().count());
    }
    @Test void blockedSiteMapDoesNotBlockFurtherCapturesOrStats() throws Exception {
        CountDownLatch enteredSiteMap = new CountDownLatch(1);
        CountDownLatch releaseSiteMap = new CountDownLatch(1);
        var field = EventManager.class.getDeclaredField("siteMapExecutor");
        field.setAccessible(true);
        var siteMapWorker = (ThreadPoolExecutor) field.get(manager);
        siteMapWorker.execute(() -> {
            enteredSiteMap.countDown();
            try { releaseSiteMap.await(5, TimeUnit.SECONDS); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        });
        try {
            assertTrue(enteredSiteMap.await(2, TimeUnit.SECONDS));
            manager.processEvent(event("4242_1_app_7_1", 1,
                    "GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            manager.processEvent(event("4242_1_app_7_0", 3,
                    "HTTP/1.1 200 OK\r\n\r\n"));
            assertEquals(1, siteMapWorker.getQueue().size());
            ExecutorService capture = Executors.newSingleThreadExecutor();
            try {
                Future<Long> result = capture.submit(() -> {
                    for (int i = 0; i < 40; i++) manager.processEvent(event("", 1,
                            "GET /next/" + i + " HTTP/1.1\r\n\r\n"));
                    return manager.getTotalPairsMatched();
                });
                assertEquals(41, result.get(2, TimeUnit.SECONDS));
            } finally {
                capture.shutdownNow();
            }
        } finally {
            releaseSiteMap.countDown();
        }
    }
    @Test void distinctFileDescriptorsAreNotCrossPaired() {
        manager.processEvent(event("4242_99_proc_with_underscores_7_1", 1, "GET /fd7 HTTP/1.1\r\n\r\n"));
        manager.processEvent(event("4242_99_proc_with_underscores_8_1", 1, "GET /fd8 HTTP/1.1\r\n\r\n"));
        manager.processEvent(event("4242_100_proc_with_underscores_8_0", 3, "HTTP/1.1 202 OK\r\n\r\n"));
        assertFalse(manager.getMatchedPairs().get(0).hasResponse());
        assertEquals("202", manager.getMatchedPairs().get(1).getStatusCode());
    }
    @Test void informationalResponseDoesNotConsumeRequest() {
        manager.processEvent(event("4242_1_app_7_1", 1, "POST / HTTP/1.1\r\n\r\n"));
        manager.processEvent(event("4242_1_app_7_0", 3, "HTTP/1.1 100 Continue\r\n\r\n"));
        manager.processEvent(event("4242_1_app_7_0", 3, "HTTP/1.1 201 Created\r\n\r\n"));
        assertEquals(1, manager.getMatchedPairs().size());
        assertEquals("201", manager.getMatchedPairs().get(0).getStatusCode());
    }
    @Test void metadataLessResponsesRemainVisibleWithoutGuessingPairs() throws Exception {
        feed("http1-get"); feed("http1-response");
        assertEquals(2, manager.getMatchedPairs().size());
        assertFalse(manager.getMatchedPairs().get(0).hasResponse());
        assertEquals("200", manager.getMatchedPairs().get(1).getStatusCode());
    }
    @Test void unparsedDataIsNotSilentAndMalformedFramesDoNotKillNextEvent() throws Exception {
        manager.processEvent(event("", 0, "not-http"));
        assertEquals(1, manager.getUnparsedEvents());
        assertTrue(manager.getRuntimeLogs().get(0).contains("not-http"));
        feed(new byte[]{0x12, (byte)0xff});
        feed("http1-get");
        assertEquals(1, manager.getTotalPairsMatched());
        assertTrue(manager.getRuntimeLogs().stream().anyMatch(s -> s.contains("Invalid protobuf")));
    }
    @Test void heartbeatActuallyTestedAndDoesNotCountAsHttpEvent() throws Exception {
        feed("heartbeat");
        assertTrue(manager.getLastHeartbeatTime() > 0);
        assertEquals(0, manager.getTotalEventsReceived());
        assertTrue(manager.getMatchedPairs().isEmpty());
    }
    @Test void clearClearsPendingConnectionsAndStreamState() {
        manager.processEvent(event("4242_1_app_7_1", 1, "GET /old HTTP/1.1\r\n\r\n"));
        manager.clear();
        manager.processEvent(event("4242_1_app_7_0", 3, "HTTP/1.1 200 OK\r\n\r\n"));
        assertEquals(1, manager.getMatchedPairs().size());
        assertFalse(manager.getMatchedPairs().get(0).hasRequest());
        assertEquals(0, manager.getPendingPairsCount());
    }
    static String headers(int id, String fields) {
        return "\nFrame Type\t=>\tHEADERS\nFrame StreamID\t=>\t" + id + "\nFrame Length\t=>\t20\n" + fields;
    }
    @Test void http2BodiesAndOutOfOrderResponsesStayOnTheirStream() {
        manager.processEvent(event("4242_1_app_7_1", 2,
                headers(1, "header field \":method\" = \"POST\"\nheader field \":path\" = \"/one\"\n")
                + headers(3, "header field \":method\" = \"GET\"\nheader field \":path\" = \"/three\"\n")));
        manager.processEvent(event("4242_1_app_7_1", 2,
                "\nFrame Type\t=>\tDATA\nFrame StreamID\t=>\t1\nFrame Length\t=>\t4\n\u0000\u00ff\u0080A\n"));
        manager.processEvent(event("4242_1_app_7_0", 4,
                headers(3, "header field \":status\" = \"203\"\n")
                + headers(1, "header field \":status\" = \"201\"\n")));
        var pairs = manager.getMatchedPairs();
        assertEquals(2, pairs.size());
        assertEquals("201", pairs.get(0).getStatusCode());
        assertEquals("203", pairs.get(1).getStatusCode());
        byte[] payload = pairs.get(0).getRequest().getPayload();
        assertArrayEquals(new byte[]{0,(byte)255,(byte)128,65},
                Arrays.copyOfRange(payload, payload.length - 4, payload.length));
    }
    @Test void endpointPrefixRestoresHostPortAndConnection() {
        manager.processEvent(event("", 0, "PID:99, Comm:my_process, Src:127.0.0.1:45000, Dest:127.0.0.2:8443,\n"
                + "GET / HTTP/1.0\r\n\r\n"));
        var pair = manager.getMatchedPairs().get(0);
        assertEquals("127.0.0.2", pair.getHost());
        assertEquals(8443, pair.getPort());
        assertTrue(pair.isHttps());
    }
    @Test void futureUnknownProtobufFieldsDoNotBreakDisplay() throws Exception {
        byte[] data = fixture("http1-get");
        var out = new java.io.ByteArrayOutputStream();
        out.writeBytes(data);
        out.writeBytes(new byte[]{(byte)0xA0, 0x06, 0x01}); // unknown field 100
        feed(out.toByteArray());
        assertEquals(1, manager.getTotalPairsMatched());
    }
    @ParameterizedTest @ValueSource(strings = {"direct-post-long", "direct-soap",
            "direct-json-response", "direct-chunked-response", "direct-binary", "direct-lf"})
    void actualOpenSslFixturesRetainEveryHttpByte(String name) throws Exception {
        feed(name);
        assertEquals(1, manager.getMatchedPairs().size());
        var pair = manager.getMatchedPairs().get(0);
        var message = pair.hasRequest() ? pair.getRequest() : pair.getResponse();
        assertArrayEquals(resource(name + ".http"), message.getPayload());
        assertArrayEquals(resource(name + ".payload"), message.getRawPayload());
        assertEquals(22399, message.getPid());
        assertFalse(message.getProcessName().isEmpty());
        assertTrue(pair.getTimestamp().matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3}"));
        assertEquals(0, manager.getUnparsedEvents());
    }
    @Test void exactReportedTimestampAndProcessWithSpacesAreRecognized() {
        manager.processEvent(event("", 0,
                "[2026-09-22 18:17:47.438] PID:22399 TID:22490 Comm:GIBSDK Network  FD:9 WRITE (999 bytes):\n"
                + "POST /api/fl?as=test HTTP/1.1\nHost: telemetry.example.invalid\n\nsynthetic"));
        var pair = manager.getMatchedPairs().get(0);
        assertEquals("POST", pair.getMethod());
        assertEquals("/api/fl?as=test", pair.getUrl());
        assertEquals("GIBSDK Network", pair.getRequest().getProcessName());
        assertEquals("2026-09-22 18:17:47.438", pair.getTimestamp());
        assertTrue(new String(pair.getRequest().getPayload(), StandardCharsets.ISO_8859_1).endsWith("synthetic"));
    }
    @Test void reportedZeroFdReadAndWriteBothAppearWithoutFalsePairing() {
        manager.processEvent(event("", 0,
                "[2026-09-22 18:18:05.894] PID:22399 TID:22698 Comm:RxCachedThreadS FD:0 WRITE (99 bytes):\n"
                + "POST /SAPI/MAWS/ HTTP/1.1\nHost: api.example.invalid\n\n<test/>"));
        manager.processEvent(event("", 0,
                "[2026-09-22 18:18:06.026] PID:22399 TID:22698 Comm:RxCachedThreadS FD:0 READ (99 bytes):\n"
                + "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n2\nOK\n0\n\n"));
        assertEquals(2, manager.getMatchedPairs().size());
        assertEquals("/SAPI/MAWS/", manager.getMatchedPairs().get(0).getUrl());
        assertEquals("200", manager.getMatchedPairs().get(1).getStatusCode());
        assertFalse(manager.getMatchedPairs().get(0).hasResponse());
        assertEquals(0, manager.getUnparsedEvents());
    }
    @Test void directKnownFdCanPairWithoutLosingThreadOrProcessData() {
        manager.processEvent(event("", 0,
                "[2026-09-22 18:18:05.894] PID:22399 TID:22698 Comm:test thread FD:9 WRITE (99 bytes):\n"
                + "POST /pair HTTP/1.1\r\n\r\n"));
        manager.processEvent(event("", 0,
                "[2026-09-22 18:18:06.026] PID:22399 TID:22699 Comm:other thread FD:9 READ (99 bytes):\n"
                + "HTTP/1.1 200 OK\r\n\r\n"));
        assertEquals(1, manager.getMatchedPairs().size());
        assertTrue(manager.getMatchedPairs().get(0).isComplete());
    }
    @Test void tupleRecordsAreMetadataNotMalformedHttp() throws Exception {
        feed("direct-tuple"); feed("direct-zero-tuple");
        assertEquals(2, manager.getTotalEventsReceived());
        assertEquals(2, manager.getMetadataEvents());
        assertEquals(0, manager.getUnparsedEvents());
        assertTrue(manager.getMatchedPairs().isEmpty());
        assertTrue(manager.getRuntimeLogs().isEmpty());
        manager.clear();
        assertEquals(0, manager.getMetadataEvents());
    }
    @Test void prefixInsideAnHttpBodyMustNotBeStripped() {
        String http = "POST / HTTP/1.1\r\n\r\n[2026-09-22 18:18:06.026] PID:1 TID:2 Comm:test FD:0 WRITE (1 bytes):\nx";
        var source = event("", 0, http);
        assertArrayEquals(source.getPayload(), CollectorEventDecoder.decode(source).getPayload());
    }
    @Test void emptyProcessAndCrlfEnvelopeAreSupported() {
        manager.processEvent(event("", 0,
                "[2026-09-22 18:18:05.894] PID:22399 TID:22698 Comm: FD:0 WRITE (99 bytes):\r\n"
                + "OPTIONS * HTTP/1.1\r\n\r\n"));
        assertEquals("OPTIONS", manager.getMatchedPairs().get(0).getMethod());
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void actualWebSocketToSwingTableAndEditorBytes(boolean directOpenSsl) throws Exception {
        List<String> fixtureNames = directOpenSsl
                ? List.of("direct-post-long", "direct-soap", "direct-json-response",
                    "direct-chunked-response", "direct-binary", "direct-lf", "direct-tuple", "direct-zero-tuple")
                : List.of("http1-get", "http1-patch", "http1-response", "http2-multiplex", "nested");
        byte[] expectedLong = directOpenSsl ? resource("direct-post-long.http") : null;
        byte[] expectedChunked = directOpenSsl ? resource("direct-chunked-response.http") : null;
        var requestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
        var responseEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        AtomicReference<ECaptureTab> tabRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> tabRef.set(new ECaptureTab(api, client, manager)));
        CountDownLatch started = new CountDownLatch(1);
        AtomicReference<Exception> serverError = new AtomicReference<>();
        WebSocketServer server = new WebSocketServer(new InetSocketAddress("127.0.0.1", 0)) {
            @Override public void onStart() { started.countDown(); }
            @Override public void onOpen(WebSocket socket, ClientHandshake handshake) {
                try {
                    socket.send(fixture("heartbeat"));
                    for (String name : fixtureNames) socket.send(fixture(name));
                } catch (Exception e) { serverError.set(e); }
            }
            @Override public void onClose(WebSocket socket, int code, String reason, boolean remote) {}
            @Override public void onMessage(WebSocket socket, String message) {}
            @Override public void onError(WebSocket socket, Exception e) { serverError.set(e); }
        };
        server.start();
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS));
            client.connect("ws://127.0.0.1:" + server.getPort() + "/");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (manager.getTotalEventsReceived() < fixtureNames.size() && System.nanoTime() < deadline) Thread.sleep(20);
            assertEquals(directOpenSsl ? 4 : 5, manager.getTotalPairsMatched());
            assertEquals(0, manager.getUnparsedEvents());
            assertEquals(directOpenSsl ? 2 : 0, manager.getMetadataEvents());
            assertNull(serverError.get());
            SwingUtilities.invokeAndWait(() -> {
                JTable table = tabRef.get().getEventTable();
                assertEquals(6, table.getRowCount());
                assertEquals(directOpenSsl ? List.of("POST","POST","-","-","POST","PATCH")
                                : List.of("GET","PATCH","-","GET","GET","DELETE"),
                        java.util.stream.IntStream.range(0, 6).mapToObj(i -> table.getValueAt(i, 2)).toList());
                // Burp factories exist only inside Burp. Mock only that boundary;
                // keep real WebSocket, protobuf, parser, manager and Swing table.
                try (MockedStatic<ByteArray> bytes = mockStatic(ByteArray.class);
                     MockedStatic<HttpRequest> requests = mockStatic(HttpRequest.class);
                     MockedStatic<HttpResponse> responses = mockStatic(HttpResponse.class)) {
                    AtomicReference<byte[]> shown = new AtomicReference<>();
                    AtomicReference<byte[]> shownResponse = new AtomicReference<>();
                    bytes.when(() -> ByteArray.byteArray(any(byte[].class))).thenAnswer(call -> {
                        byte[] raw = (byte[]) call.getRawArguments()[0];
                        ByteArray array = mock(ByteArray.class);
                        when(array.getBytes()).thenReturn(raw);
                        return array;
                    });
                    HttpRequest request = mock(HttpRequest.class);
                    requests.when(() -> HttpRequest.httpRequest(any(ByteArray.class))).thenAnswer(call -> {
                        shown.set(((ByteArray)call.getArgument(0)).getBytes()); return request;
                    });
                    responses.when(() -> HttpResponse.httpResponse("")).thenReturn(mock(HttpResponse.class));
                    responses.when(() -> HttpResponse.httpResponse(any(ByteArray.class))).thenAnswer(call -> {
                        shownResponse.set(((ByteArray)call.getArgument(0)).getBytes());
                        return mock(HttpResponse.class);
                    });
                    int binaryRow = directOpenSsl ? 4 : 1;
                    table.setRowSelectionInterval(binaryRow, binaryRow);
                    verify(requestEditor).setRequest(request);
                    byte[] raw = shown.get();
                    assertNotNull(raw);
                    assertArrayEquals(new byte[]{0,(byte)255,(byte)128,65},
                            Arrays.copyOfRange(raw, raw.length - 4, raw.length));
                    if (directOpenSsl) {
                        table.setRowSelectionInterval(0, 0);
                        assertArrayEquals(expectedLong, shown.get());
                        assertTrue(shown.get().length > 6220);
                        table.setRowSelectionInterval(3, 3);
                        assertArrayEquals(expectedChunked, shownResponse.get());
                    } else {
                        table.setRowSelectionInterval(3, 3);
                        assertTrue(new String(shown.get(), StandardCharsets.ISO_8859_1)
                                .startsWith("GET /stream/1 HTTP/1.1\r\n"));
                    }
                }
            });
        } finally {
            tabRef.get().dispose();
            client.shutdown(); server.stop(1000);
        }
    }
}
