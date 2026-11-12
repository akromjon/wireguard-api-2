package main

import (
	"net"
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

// startEcho opens the echo socket. It returns nil, nil when ECHO_ENABLED=0.
func startEcho() (net.PacketConn, error) {
	if getEnv(echoDefaultEnabledEnv, "1") == "0" {
		return nil, nil
	}
	return net.ListenPacket("udp", ":"+getEnv("ECHO_PORT", API_PORT))
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
