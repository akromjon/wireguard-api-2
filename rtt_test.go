package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeRTT struct {
	mu          sync.Mutex
	resolveN    int
	dialAddrs   []netip.AddrPort
	dialResults []time.Duration // negative = error
	resolved    []netip.Addr
	resolveErr  error
}

func (f *fakeRTT) deps() rttDeps {
	return rttDeps{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.resolveN++
			return f.resolved, f.resolveErr
		},
		dial: func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) (time.Duration, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			i := len(f.dialAddrs)
			f.dialAddrs = append(f.dialAddrs, addr)
			if i >= len(f.dialResults) || f.dialResults[i] < 0 {
				return 0, errors.New("dial failed")
			}
			return f.dialResults[i], nil
		},
		own: func() []netip.Addr { return nil },
	}
}

func newFakeRTT(results ...time.Duration) *fakeRTT {
	return &fakeRTT{
		resolved:    []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		dialResults: results,
	}
}

var rttTestTarget = rttTarget{ID: "eu-central", Host: "example.test", Port: 443}

func TestRTTAllowedRefusesNonPublic(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	for _, s := range []string{
		"127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fd00::1", "ff02::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:203.0.113.7", "203.0.113.7",
	} {
		if rttAllowed(netip.MustParseAddr(s), own) {
			t.Errorf("%s must be refused", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "52.94.0.1", "2a00:1450::1", "::ffff:8.8.8.8"} {
		if !rttAllowed(netip.MustParseAddr(s), own) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestPickAddrPrefersIPv4(t *testing.T) {
	v6 := netip.MustParseAddr("2a00:1450::1")
	v4 := netip.MustParseAddr("8.8.8.8")
	if got, ok := pickAddr([]netip.Addr{v6, v4}); !ok || got != v4 {
		t.Errorf("[v6, v4] = %v %v, want v4", got, ok)
	}
	if got, ok := pickAddr([]netip.Addr{v6}); !ok || got != v6 {
		t.Errorf("[v6] = %v %v, want v6", got, ok)
	}
	if _, ok := pickAddr(nil); ok {
		t.Error("[] must give false")
	}
}

func TestMeasureTargetLowestOfThree(t *testing.T) {
	f := newFakeRTT(40*time.Millisecond, 23*time.Millisecond, 31*time.Millisecond)
	got := measureTarget(context.Background(), f.deps(), rttTestTarget)
	if got == nil || *got != 23 {
		t.Fatalf("got %v, want 23", got)
	}
	if len(f.dialAddrs) != 3 {
		t.Fatalf("dial called %d times, want 3", len(f.dialAddrs))
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 443)
	for _, a := range f.dialAddrs {
		if a != want {
			t.Errorf("dialed %v, want %v", a, want)
		}
	}
}

func TestMeasureTargetMinimumIsOne(t *testing.T) {
	d := 200 * time.Microsecond
	f := newFakeRTT(d, d, d)
	got := measureTarget(context.Background(), f.deps(), rttTestTarget)
	if got == nil || *got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
}

func TestMeasureTargetAllFailIsNil(t *testing.T) {
	f := newFakeRTT(-1, -1, -1)
	if got := measureTarget(context.Background(), f.deps(), rttTestTarget); got != nil {
		t.Fatalf("got %d, want nil", *got)
	}
	if len(f.dialAddrs) != 3 {
		t.Errorf("dial called %d times, want 3", len(f.dialAddrs))
	}
}

func TestMeasureTargetOneSuccessCounts(t *testing.T) {
	f := newFakeRTT(-1, 50*time.Millisecond, -1)
	got := measureTarget(context.Background(), f.deps(), rttTestTarget)
	if got == nil || *got != 50 {
		t.Fatalf("got %v, want 50", got)
	}
}

func TestMeasureTargetRefusedAddrNeverDials(t *testing.T) {
	f := newFakeRTT(10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	f.resolved = []netip.Addr{netip.MustParseAddr("10.0.0.5")}
	if got := measureTarget(context.Background(), f.deps(), rttTestTarget); got != nil {
		t.Fatalf("got %d, want nil", *got)
	}
	if len(f.dialAddrs) != 0 {
		t.Errorf("dial called %d times, want 0", len(f.dialAddrs))
	}
}

func TestMeasureTargetResolveErrorIsNil(t *testing.T) {
	f := newFakeRTT(10 * time.Millisecond)
	f.resolveErr = errors.New("no such host")
	if got := measureTarget(context.Background(), f.deps(), rttTestTarget); got != nil {
		t.Fatalf("got %d, want nil", *got)
	}
	if len(f.dialAddrs) != 0 {
		t.Errorf("dial called %d times, want 0", len(f.dialAddrs))
	}
}

func TestMeasureTargetResolvesOnce(t *testing.T) {
	f := newFakeRTT(10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	measureTarget(context.Background(), f.deps(), rttTestTarget)
	if f.resolveN != 1 {
		t.Errorf("resolve called %d times, want 1", f.resolveN)
	}
}

func TestMeasureAllKeysByID(t *testing.T) {
	f := newFakeRTT(10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond,
		10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	got := measureAll(context.Background(), f.deps(), []rttTarget{
		{ID: "a", Host: "a.test", Port: 443},
		{ID: "b", Host: "b.test", Port: 443},
	})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	for _, id := range []string{"a", "b"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing id %s", id)
		}
	}
}

func TestRTTLimiterSixPerMinute(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newRTTLimiter(6, func() time.Time { return now })
	for i := 0; i < 6; i++ {
		if !l.allow() {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	if l.allow() {
		t.Fatal("7th call must be refused")
	}
	now = now.Add(60 * time.Second)
	if !l.allow() {
		t.Fatal("call after 60s must be allowed")
	}
}
