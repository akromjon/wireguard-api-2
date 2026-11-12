package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func echoTestPacket(seq byte) []byte {
	p := make([]byte, echoPacketSize)
	copy(p, "LGN1")
	copy(p[4:12], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	p[15] = seq
	return p
}

// startTestEcho runs serveEcho on a loopback socket and returns the server
// address plus a client socket.
func startTestEcho(t *testing.T, limiter *echoLimiter) (net.Addr, net.PacketConn) {
	t.Helper()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		serveEcho(server, limiter)
		close(done)
	}()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
		<-done
	})
	return server.LocalAddr(), client
}

func echoRead(client net.PacketConn) ([]byte, bool) {
	buf := make([]byte, 2048)
	client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func newTestLimiter() *echoLimiter {
	return newEchoLimiter(echoMaxPerSecond, time.Now)
}

func TestEchoRepliesByteForByte(t *testing.T) {
	addr, client := startTestEcho(t, newTestLimiter())
	before := echoRepliesTotal.Load()
	req := echoTestPacket(3)
	if _, err := client.WriteTo(req, addr); err != nil {
		t.Fatal(err)
	}
	got, ok := echoRead(client)
	if !ok || !bytes.Equal(got, req) {
		t.Fatalf("reply = %v (ok=%v), want %v", got, ok, req)
	}
	if grew := echoRepliesTotal.Load() - before; grew != 1 {
		t.Fatalf("echoRepliesTotal grew by %d, want 1", grew)
	}
}

func TestEchoDropsWrongSize(t *testing.T) {
	addr, client := startTestEcho(t, newTestLimiter())
	for _, size := range []int{23, 25} {
		p := make([]byte, size)
		copy(p, "LGN1")
		client.WriteTo(p, addr)
		if got, ok := echoRead(client); ok {
			t.Fatalf("size %d got reply %v", size, got)
		}
	}
}

func TestEchoDropsWrongMagic(t *testing.T) {
	addr, client := startTestEcho(t, newTestLimiter())
	p := echoTestPacket(0)
	copy(p, "LGN2")
	client.WriteTo(p, addr)
	if got, ok := echoRead(client); ok {
		t.Fatalf("got reply %v", got)
	}
}

func TestEchoReplyIsNeverLargerThanRequest(t *testing.T) {
	addr, client := startTestEcho(t, newTestLimiter())
	p := make([]byte, 1200)
	copy(p, "LGN1")
	client.WriteTo(p, addr)
	if got, ok := echoRead(client); ok {
		t.Fatalf("got reply of %d bytes", len(got))
	}
}

func TestEchoRateLimit20PerSecondPerSource(t *testing.T) {
	var nowNanos atomic.Int64
	nowNanos.Store(time.Unix(1_000_000, 0).UnixNano())
	limiter := newEchoLimiter(echoMaxPerSecond, func() time.Time {
		return time.Unix(0, nowNanos.Load())
	})
	addr, client := startTestEcho(t, limiter)

	replies := 0
	for i := 0; i < 25; i++ {
		client.WriteTo(echoTestPacket(byte(i%5)), addr)
	}
	for {
		if _, ok := echoRead(client); !ok {
			break
		}
		replies++
	}
	if replies != 20 {
		t.Fatalf("replies = %d, want 20", replies)
	}

	nowNanos.Add(int64(time.Second))
	client.WriteTo(echoTestPacket(0), addr)
	if _, ok := echoRead(client); !ok {
		t.Fatal("packet after the window moved was not answered")
	}
}

func TestEchoLimiterIsPerIP(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < 20; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("call %d denied", i)
		}
	}
	if l.allow("10.0.0.1") {
		t.Fatal("21st call allowed")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("other IP denied")
	}
}

func TestEchoLimiterCapsTrackedIPs(t *testing.T) {
	l := newEchoLimiter(echoMaxPerSecond, func() time.Time { return time.Unix(5, 0) })
	for i := 0; i < echoMaxTrackedIPs; i++ {
		if !l.allow(string(rune(i)) + "x") {
			t.Fatalf("IP %d denied under the cap", i)
		}
	}
	if l.allow("one-more") {
		t.Fatal("IP over the cap was allowed")
	}
}

func TestStartEchoDisabledByEnv(t *testing.T) {
	t.Setenv("ECHO_ENABLED", "0")
	conn, err := startEcho()
	if conn != nil || err != nil {
		t.Fatalf("got %v, %v; want nil, nil", conn, err)
	}
}

func TestStatsPayloadCarriesEchoCounter(t *testing.T) {
	p := statsPayload("eth0", 1, 2, 3)
	if p["echo_replies_total"] != echoRepliesTotal.Load() {
		t.Fatalf("echo_replies_total = %v", p["echo_replies_total"])
	}
	for _, k := range []string{"interface", "profile", "rx_bytes", "tx_bytes", "peers", "uptime_seconds"} {
		if _, ok := p[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
}

// freeUDPPort returns a UDP port number that is free right now.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	return port
}

// withVPNFiles points the port discovery at a temp dir holding the given
// files (name -> content) and clears the other inputs.
func withVPNFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldDirs, oldParams, oldCfg := vpnPortDirs, WG_PARAMS_FILE, WG_CONFIG_FILE
	vpnPortDirs = []string{dir}
	WG_PARAMS_FILE = filepath.Join(dir, "params")
	WG_CONFIG_FILE = filepath.Join(dir, "awg0.conf")
	t.Cleanup(func() { vpnPortDirs, WG_PARAMS_FILE, WG_CONFIG_FILE = oldDirs, oldParams, oldCfg })
	return dir
}

func TestStartEchoRefusesPortOfAWGInterfaceConfig(t *testing.T) {
	port := freeUDPPort(t)
	withVPNFiles(t, map[string]string{
		"awg0.conf": "[Interface]\nPrivateKey = x\nListenPort = 1111\n",
		"awg1.conf": "[Interface]\nPrivateKey = y\nListenPort = " + port + "\n",
	})
	t.Setenv("ECHO_ENABLED", "1")
	t.Setenv("ECHO_PORT", port)
	conn, err := startEcho()
	if conn != nil {
		conn.Close()
		t.Fatal("echo listened on an AWG listen port")
	}
	if err != nil {
		t.Fatalf("err = %v; want nil", err)
	}
}

func TestStartEchoRefusesPortOfParamsServerPort(t *testing.T) {
	port := freeUDPPort(t)
	withVPNFiles(t, map[string]string{"params": "SERVER_PORT=\"" + port + "\"\nSERVER_AWG_NIC=awg0\n"})
	t.Setenv("ECHO_ENABLED", "1")
	t.Setenv("ECHO_PORT", port)
	conn, err := startEcho()
	if conn != nil {
		conn.Close()
		t.Fatal("echo listened on SERVER_PORT")
	}
	if err != nil {
		t.Fatalf("err = %v; want nil", err)
	}
}

func TestStartEchoStartsWhenPortDiffers(t *testing.T) {
	port := freeUDPPort(t)
	withVPNFiles(t, map[string]string{
		"awg0.conf": "[Interface]\nListenPort = 1111\n",
		"params":    "SERVER_PORT=2222\n",
	})
	t.Setenv("ECHO_ENABLED", "1")
	t.Setenv("ECHO_PORT", port)
	conn, err := startEcho()
	if err != nil || conn == nil {
		t.Fatalf("got %v, %v; want a listener", conn, err)
	}
	conn.Close()
}

func TestStartEchoStartsWhenConfigsUnreadable(t *testing.T) {
	port := freeUDPPort(t)
	withVPNFiles(t, nil) // no params, no configs
	vpnPortDirs = []string{filepath.Join(t.TempDir(), "missing")}
	t.Setenv("ECHO_ENABLED", "1")
	t.Setenv("ECHO_PORT", port)
	conn, err := startEcho()
	if err != nil || conn == nil {
		t.Fatalf("got %v, %v; want a listener", conn, err)
	}
	conn.Close()
}

func TestStartEchoIgnoresGarbageInConfigs(t *testing.T) {
	port := freeUDPPort(t)
	withVPNFiles(t, map[string]string{
		"awg0.conf": "ListenPort = notanumber\nListenPort=\n",
		"params":    "SERVER_PORT=\n",
	})
	t.Setenv("ECHO_ENABLED", "1")
	t.Setenv("ECHO_PORT", port)
	conn, err := startEcho()
	if err != nil || conn == nil {
		t.Fatalf("got %v, %v; want a listener", conn, err)
	}
	conn.Close()
}

func TestServeEchoLogsOnceOnReadError(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	serveEcho(failingConn{}, newEchoLimiter(echoMaxPerSecond, time.Now))
	if got := strings.Count(buf.String(), "UDP echo stopped"); got != 1 {
		t.Fatalf("want one stop line, got %d: %q", got, buf.String())
	}
}

type failingConn struct{ net.PacketConn }

func (failingConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, errors.New("boom") }
