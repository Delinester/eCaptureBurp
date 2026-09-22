// Copy into the v2.6.0 checkout's internal/probe/openssl directory to regenerate.
// Uses the actual Event.String -> TextHandler -> Server.WriteEvent path.
// All HTTP bodies, hosts and header values are synthetic.
package openssl

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture/v2/internal/probe/base/handlers"
	eq "github.com/gojue/ecapture/v2/pkg/ecaptureq"
	pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type burpFixtureWriter struct{ server *eq.Server }

func (w burpFixtureWriter) Write(data []byte) (int, error) { return w.server.WriteEvent(data) }
func (w burpFixtureWriter) Close() error                   { return nil }
func (w burpFixtureWriter) Flush() error                   { return nil }
func (w burpFixtureWriter) Name() string                   { return "burp-loopback-test" }

func TestBurpDirectOutputFixtures(t *testing.T) {
	out := os.Getenv("BURP_FIXTURE_DIR")
	if out == "" {
		t.Skip("set BURP_FIXTURE_DIR to generate fixtures")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(os.MkdirAll(out, 0755))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	addr := listener.Addr().String()
	check(listener.Close())
	server := eq.NewServer(addr, io.Discard)
	go func() { _ = server.Start() }()
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
		check(ws.SetDeadline(time.Now().Add(10 * time.Second)))
		var data []byte
		check(websocket.Message.Receive(ws, &data))
		return data
	}
	_ = receive() // Initial heartbeat proves registration has completed.
	writer := burpFixtureWriter{server: server}
	handler := handlers.NewTextHandler(writer, false)
	save := func(name string, original []byte) {
		wire := receive()
		var entry pb.LogEntry
		check(proto.Unmarshal(wire, &entry))
		event := entry.GetEventPayload()
		if event == nil {
			t.Fatal("expected event frame")
		}
		check(os.WriteFile(filepath.Join(out, name+".bin"), wire, 0644))
		check(os.WriteFile(filepath.Join(out, name+".payload"), event.Payload, 0644))
		if original != nil {
			check(os.WriteFile(filepath.Join(out, name+".http"), original, 0644))
		}
		t.Logf("%s: wire=%d payload=%d bytes", name, len(wire), len(event.Payload))
	}
	produce := func(name, comm string, fd uint32, direction int64, data []byte) {
		var mono unix.Timespec
		check(unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono))
		event := &Event{Timestamp: uint64(mono.Nano()), Pid: 22399, Tid: 22490,
			Fd: fd, DataType: direction, DataLen: int32(len(data))}
		copy(event.Comm[:], []byte(comm))
		copy(event.Data[:], data)
		check(handler.Handle(event))
		save(name, data)
	}
	body := bytes.Repeat([]byte("A"), 6220)
	post := []byte(fmt.Sprintf("POST /api/fl?as=test HTTP/1.1\r\nContent-Type: application/octet-stream\r\n"+
		"Cookie: test-cookie=synthetic\r\nContent-Length: %d\r\nHost: telemetry.example.invalid\r\n"+
		"Connection: Keep-Alive\r\n\r\n", len(body)))
	post = append(post, body...)
	produce("direct-post-long", "GIBSDK Network ", 9, DataTypeWrite, post)
	soap := []byte("<Envelope><Body><test>synthetic</test></Body></Envelope>")
	request := []byte(fmt.Sprintf("POST /SAPI/MAWS/ HTTP/1.1\r\nContent-Type: text/xml; charset=utf-8\r\n"+
		"Content-Length: %d\r\nHost: api.example.invalid\r\n\r\n", len(soap)))
	request = append(request, soap...)
	produce("direct-soap", "RxCachedThreadS", 0, DataTypeWrite, request)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}")
	produce("direct-json-response", "GIBSDK Network ", 0, DataTypeRead, response)
	xml := []byte("<Envelope><message>Успешно</message></Envelope>")
	chunked := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(xml), xml))
	produce("direct-chunked-response", "RxCachedThreadS", 0, DataTypeRead, chunked)
	binary := []byte("POST /binary HTTP/1.1\r\nHost: binary.example.invalid\r\nContent-Length: 4\r\n\r\n")
	binary = append(binary, 0, 255, 128, 65)
	produce("direct-binary", "binary_test", 11, DataTypeWrite, binary)
	// Match the user's LF-only presentation as well as native CRLF messages.
	lf := []byte(strings.ReplaceAll("PATCH /lf HTTP/1.1\r\nHost: lf.example.invalid\r\n\r\n", "\r\n", "\n"))
	produce("direct-lf", "test with space", 12, DataTypeWrite, lf)

	for _, item := range []struct {
		name, tuple  string
		pid, tid, fd uint32
	}{
		{"direct-tuple", "[::ffff:192.0.2.40]:33916->[::ffff:198.51.100.239]:443", 22399, 22490, 132},
		{"direct-zero-tuple", "[::]:0->[::]:0", 0, 0, 0},
	} {
		event := &ConnDataEvent{Tuple: item.tuple}
		event.Pid, event.Tid, event.Fd = item.pid, item.tid, item.fd
		if item.pid != 0 {
			copy(event.Comm[:], []byte("GIBSDK Network"))
		}
		_, err = writer.Write([]byte(event.String() + "\n"))
		check(err)
		save(item.name, nil)
	}
}
