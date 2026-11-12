package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UDP echo for phone-to-server latency probes.
//
// Packet: exactly 24 bytes, "LGN1" + 8 id bytes + 4 sequence bytes + 8 zero
// bytes. The reply is the same 24 bytes sent back to the sender. Anything
// else is dropped without a reply, so the reply is never larger than the
// request and the port cannot be used for amplification.
const (
	echoPacketSize        = 24
	echoMaxPerSecond      = 20
	echoMaxTrackedIPs     = 50000
	echoReadBufferSize    = 64 // larger than a packet so longer datagrams are seen as longer
	echoMagic             = "LGN1"
	echoDefaultEnabledEnv = "ECHO_ENABLED"
)

var echoRepliesTotal atomic.Uint64

func validEchoPacket(b []byte) bool {
	return len(b) == echoPacketSize && string(b[:len(echoMagic)]) == echoMagic
}

// echoLimiter allows at most perSecond replies per source IP in a fixed
// one-second window. The table is dropped at each new second and holds at
// most echoMaxTrackedIPs addresses; beyond that new addresses are denied.
type echoLimiter struct {
	mu        sync.Mutex
	perSecond int
	now       func() time.Time
	window    int64
	counts    map[string]int
}

func newEchoLimiter(perSecond int, now func() time.Time) *echoLimiter {
	return &echoLimiter{
		perSecond: perSecond,
		now:       now,
		counts:    make(map[string]int),
	}
}

func (l *echoLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if sec := l.now().Unix(); sec != l.window {
		l.window = sec
		l.counts = make(map[string]int)
	}
	n, seen := l.counts[ip]
	if !seen && len(l.counts) >= echoMaxTrackedIPs {
		return false
	}
	if n >= l.perSecond {
		return false
	}
	l.counts[ip] = n + 1
	return true
}

// serveEcho answers valid echo packets until conn is closed. It logs nothing
// per packet.
func serveEcho(conn net.PacketConn, limiter *echoLimiter) {
	buf := make([]byte, echoReadBufferSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("UDP echo stopped: %v", err)
			return
		}
		if !validEchoPacket(buf[:n]) {
			continue
		}
		ip := ""
		if udp, ok := addr.(*net.UDPAddr); ok {
			ip = udp.IP.String()
		} else {
			ip = addr.String()
		}
		if !limiter.allow(ip) {
			continue
		}
		if _, err := conn.WriteTo(buf[:echoPacketSize], addr); err == nil {
			echoRepliesTotal.Add(1)
		}
	}
}

// vpnPortDirs are the directories scanned for AmneziaWG/WireGuard interface
// configs (*.conf) and params files (params*). The directory of WG_CONFIG_FILE
// is scanned as well.
var vpnPortDirs = []string{"/etc/amnezia/amneziawg", "/etc/wireguard"}

// parseKeyPort returns the port in a "KEY = value" line when the key matches.
func parseKeyPort(line, key string) (int, bool) {
	k, v, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(k) != key {
		return 0, false
	}
	n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), "\"'"))
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

func collectPorts(path, key string, ports map[int]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if n, ok := parseKeyPort(sc.Text(), key); ok {
			ports[n] = true
		}
	}
}

// vpnListenPorts returns the UDP ports that AmneziaWG/WireGuard interfaces on
// this box listen on: SERVER_PORT of the params file(s) and ListenPort of every
// interface config. It reads a few small files once and never runs commands.
// The set is empty when nothing could be read.
func vpnListenPorts() map[int]bool {
	ports := map[int]bool{}
	collectPorts(WG_PARAMS_FILE, "SERVER_PORT", ports)
	collectPorts(WG_CONFIG_FILE, "ListenPort", ports)
	dirs := append([]string{filepath.Dir(WG_CONFIG_FILE)}, vpnPortDirs...)
	for _, dir := range dirs {
		confs, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, c := range confs {
			collectPorts(c, "ListenPort", ports)
		}
		params, _ := filepath.Glob(filepath.Join(dir, "params*"))
		for _, p := range params {
			collectPorts(p, "SERVER_PORT", ports)
		}
	}
	return ports
}

// startEcho opens the echo socket. It returns nil, nil when ECHO_ENABLED=0 or
// when the echo port is a VPN listen port on this box: the VPN must always be
// able to bind its port, so echo yields.
func startEcho() (net.PacketConn, error) {
	if getEnv(echoDefaultEnabledEnv, "1") == "0" {
		return nil, nil
	}
	port := getEnv("ECHO_PORT", API_PORT)
	vpnPorts := vpnListenPorts()
	if len(vpnPorts) == 0 {
		log.Printf("UDP echo: VPN listen ports could not be determined, port check skipped")
	} else if n, err := strconv.Atoi(port); err == nil && vpnPorts[n] {
		log.Printf("UDP echo not started: port %s is a VPN listen port on this box", port)
		return nil, nil
	}
	return net.ListenPacket("udp", ":"+port)
}

// statsPayload is the body of a successful /stats response.
func statsPayload(billNIC string, rx, tx uint64, peers int) map[string]interface{} {
	return map[string]interface{}{
		"interface": billNIC,
		"profile":   AWG_PROFILE,
		"rx_bytes":  rx,
		"tx_bytes":  tx,
		"peers":     peers,
		// Counters are cumulative since the interface came up, so the
		// consumer needs this to turn them into a rate.
		"uptime_seconds":     systemUptimeSeconds(),
		"echo_replies_total": echoRepliesTotal.Load(),
	}
}
