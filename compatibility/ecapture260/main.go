// Generates fixtures through the unmodified v2.6.0 event processor and
// ecaptureq.Server.WriteEvent over a real loopback WebSocket. No eBPF needed.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	eq "github.com/gojue/ecapture/v2/pkg/ecaptureq"
	ep "github.com/gojue/ecapture/v2/pkg/event_processor"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

type writer struct{ server *eq.Server }

func (w writer) Write(b []byte) (int, error) { return w.server.WriteEvent(b) }

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run . OUTPUT_DIRECTORY")
	}
	out := os.Args[1]
	check(os.MkdirAll(out, 0755))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	addr := listener.Addr().String()
	check(listener.Close())
	server := eq.NewServer(addr, io.Discard)
	go func() { check(server.Start()) }()
	var ws *websocket.Conn
	for i := 0; i < 100; i++ {
		ws, err = websocket.Dial("ws://"+addr+"/", "", "http://localhost/")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	check(err)
	defer ws.Close()
	receive := func() []byte {
		check(ws.SetDeadline(time.Now().Add(15 * time.Second)))
		var data []byte
		check(websocket.Message.Receive(ws, &data))
		return data
	}
	heartbeat := receive()
	check(os.WriteFile(filepath.Join(out, "heartbeat.bin"), heartbeat, 0644))
	// Wait for the initial heartbeat: proves registration is complete.
	var hb pb.LogEntry
	check(proto.Unmarshal(heartbeat, &hb))
	if hb.GetHeartbeatPayload() == nil {
		panic("expected initial heartbeat")
	}

	produce := func(name string, payload []byte, direction int64) {
		event := &ep.BaseEvent{Pid: 4242, Tid: 4243, Fd: 7, DataType: direction,
			Timestamp: 1780000000000000000, DataLen: int32(len(payload))}
		copy(event.Comm[:], []byte("fixture_client"))
		copy(event.Data[:], payload)
		processor := ep.NewEventProcessor(writer{server}, false, 0)
		go func() { check(processor.Serve()) }()
		processor.Write(event)
		check(processor.Close())
		for {
			data := receive()
			var entry pb.LogEntry
			check(proto.Unmarshal(data, &entry))
			if entry.GetEventPayload() == nil {
				continue
			}
			check(os.WriteFile(filepath.Join(out, name+".bin"), data, 0644))
			check(os.WriteFile(filepath.Join(out, name+".payload"), entry.GetEventPayload().Payload, 0644))
			fmt.Printf("%s: type=%d uuid=%q payload-prefix=%q\n", name,
				entry.GetEventPayload().Type, entry.GetEventPayload().Uuid,
				entry.GetEventPayload().Payload[:min(100, len(entry.GetEventPayload().Payload))])
			break
		}
	}
	produce("http1-get", []byte("GET /from-ecapture-260 HTTP/1.1\r\nHost: example.test\r\n\r\n"), 1)
	produce("http1-patch", []byte("PATCH /binary HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n\x00\xff\x80A"), 1)
	produce("http1-response", []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"), 0)

	var h2 bytes.Buffer
	h2.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&h2, nil)
	check(framer.WriteSettings())
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, id := range []uint32{1, 3} {
		block.Reset()
		for _, header := range []hpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "h2.example.test"},
			{Name: ":path", Value: fmt.Sprintf("/stream/%d", id)},
		} {
			check(encoder.WriteField(header))
		}
		check(framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}))
	}
	produce("http2-multiplex", h2.Bytes(), 1)

	h2.Reset()
	h2.WriteString(http2.ClientPreface)
	block.Reset()
	encoder = hpack.NewEncoder(&block)
	for _, header := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "h2.example.test"},
		{Name: ":path", Value: "/binary"},
	} {
		check(encoder.WriteField(header))
	}
	check(framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 5, BlockFragment: block.Bytes(), EndHeaders: true}))
	check(framer.WriteData(5, true, []byte{0, 255, 128, 65}))
	produce("http2-post", h2.Bytes(), 1)

	h2.Reset()
	block.Reset()
	encoder = hpack.NewEncoder(&block)
	check(framer.WriteSettings())
	for _, header := range []hpack.HeaderField{
		{Name: ":status", Value: "200"}, {Name: "content-encoding", Value: "gzip"},
	} {
		check(encoder.WriteField(header))
	}
	check(framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 5, BlockFragment: block.Bytes(), EndHeaders: true}))
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	_, err = zip.Write([]byte("decompressed-body"))
	check(err)
	check(zip.Close())
	check(framer.WriteData(5, true, compressed.Bytes()))
	produce("http2-gzip-response", h2.Bytes(), 0)

	// Alternate producer branch: a serialized LogEntry wrapped in WriteEvent.
	inner := &pb.LogEntry{LogType: pb.LogType_LOG_TYPE_EVENT,
		Payload: &pb.LogEntry_EventPayload{EventPayload: &pb.Event{
			Uuid: "4242_4243_fixture_client_7_1", Pid: 4242, Pname: "fixture_client", Type: 1,
			Payload: []byte("DELETE /nested HTTP/1.1\r\nHost: nested.example.test\r\n\r\n")}}}
	encoded, err := proto.Marshal(inner)
	check(err)
	_, err = server.WriteEvent(encoded)
	check(err)
	check(os.WriteFile(filepath.Join(out, "nested.bin"), receive(), 0644))
}
