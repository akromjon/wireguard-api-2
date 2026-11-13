package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// TCP connect timing for the backend's region probes.
//
// The backend sends a list of targets; this node connects to each one on
// port 443 and reports the lowest connect time. Because the caller chooses the
// host, every address is checked before any connection is made, so the node
// cannot be used to reach private, loopback or its own addresses.
const (
	rttMaxTargets   = 16
	rttPort         = 443
	rttTries        = 3
	rttTimeout      = 1000 * time.Millisecond
	rttMaxPerMinute = 6
	rttMaxBodyBytes = 8 << 10
	rttMaxIDLen     = 64
)

type rttTarget struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

var rttCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// rttAllowed reports whether addr is a public address this node may connect
// to. An IPv4-mapped IPv6 address is judged as the IPv4 address inside it.
func rttAllowed(addr netip.Addr, own []netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		rttCGNAT.Contains(addr) ||
		addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, o := range own {
		if o.Unmap() == addr {
			return false
		}
	}
	return true
}

// ownAddrs returns every address of every local interface, unmapped.
func ownAddrs() []netip.Addr {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifaces {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

type rttDeps struct {
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) (time.Duration, error)
	own     func() []netip.Addr
}

func defaultRTTDeps() rttDeps {
	return rttDeps{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for i := range addrs {
				addrs[i] = addrs[i].Unmap()
			}
			return addrs, nil
		},
		dial: func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) (time.Duration, error) {
			d := net.Dialer{Timeout: timeout}
			start := time.Now()
			conn, err := d.DialContext(ctx, "tcp", addr.String())
			elapsed := time.Since(start)
			if err != nil {
				return 0, err
			}
			conn.Close()
			return elapsed, nil
		},
		own: ownAddrs,
	}
}

// pickAddr takes the first IPv4 address if there is one, else the first
// address.
func pickAddr(addrs []netip.Addr) (netip.Addr, bool) {
	if len(addrs) == 0 {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), true
		}
	}
	return addrs[0].Unmap(), true
}

// measureTarget resolves the host once, checks the one chosen address, then
// connects rttTries times and returns the lowest time in whole milliseconds
// (at least 1). nil means no result.
func measureTarget(ctx context.Context, d rttDeps, t rttTarget) *int {
	addrs, err := d.resolve(ctx, t.Host)
	if err != nil {
		return nil
	}
	addr, ok := pickAddr(addrs)
	if !ok || !rttAllowed(addr, d.own()) {
		return nil
	}
	target := netip.AddrPortFrom(addr, rttPort)
	best := -1
	for i := 0; i < rttTries; i++ {
		took, err := d.dial(ctx, target, rttTimeout)
		if err != nil {
			continue
		}
		ms := int(took / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		if best < 0 || ms < best {
			best = ms
		}
	}
	if best < 0 {
		return nil
	}
	return &best
}

// measureAll measures every target in parallel and keys the results by id.
func measureAll(ctx context.Context, d rttDeps, targets []rttTarget) map[string]*int {
	out := make(map[string]*int, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t rttTarget) {
			defer wg.Done()
			r := measureTarget(ctx, d, t)
			mu.Lock()
			out[t.ID] = r
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return out
}

// rttLimiter allows at most perMinute requests for the whole route in a
// fixed one-minute window.
type rttLimiter struct {
	mu        sync.Mutex
	perMinute int
	now       func() time.Time
	window    int64
	count     int
}

func newRTTLimiter(perMinute int, now func() time.Time) *rttLimiter {
	return &rttLimiter{perMinute: perMinute, now: now}
}

func (l *rttLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if w := l.now().Unix() / 60; w != l.window {
		l.window = w
		l.count = 0
	}
	if l.count >= l.perMinute {
		return false
	}
	l.count++
	return true
}
