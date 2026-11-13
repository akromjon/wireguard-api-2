package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
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
		own: func() ([]netip.Addr, error) { return nil, nil },
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
		"0.1.2.3", "240.0.0.1", "198.18.0.1", "198.19.255.255",
		"fec0::1", "64:ff9b::808:808", "2002:808:808::1",
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
	deps := rttDeps{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "bad.test" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) (time.Duration, error) {
			return 17 * time.Millisecond, nil
		},
		own: func() ([]netip.Addr, error) { return nil, nil },
	}
	got := measureAll(context.Background(), deps, []rttTarget{
		{ID: "a", Host: "a.test", Port: 443},
		{ID: "b", Host: "bad.test", Port: 443},
	})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got["a"] == nil || *got["a"] != 17 {
		t.Errorf("a = %v, want 17", got["a"])
	}
	if v, ok := got["b"]; !ok || v != nil {
		t.Errorf("b = %v (present %v), want present and nil", v, ok)
	}
}

func TestMeasureTargetOwnAddrsErrorFailsClosed(t *testing.T) {
	f := newFakeRTT(10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	d := f.deps()
	d.own = func() ([]netip.Addr, error) { return nil, errors.New("no interfaces") }
	if got := measureTarget(context.Background(), d, rttTestTarget); got != nil {
		t.Fatalf("got %d, want nil", *got)
	}
	if len(f.dialAddrs) != 0 {
		t.Errorf("dial called %d times, want 0", len(f.dialAddrs))
	}
	all := measureAll(context.Background(), d, []rttTarget{
		{ID: "a", Host: "a.test", Port: 443}, {ID: "b", Host: "b.test", Port: 443},
	})
	if v, ok := all["a"]; !ok || v != nil {
		t.Errorf("a = %v, want present and nil", v)
	}
	if v, ok := all["b"]; !ok || v != nil {
		t.Errorf("b = %v, want present and nil", v)
	}
	if len(f.dialAddrs) != 0 {
		t.Errorf("dial called %d times, want 0", len(f.dialAddrs))
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

func TestRTTLimiterSameWindowStaysRefused(t *testing.T) {
	now := time.Unix(1_700_000_040, 0) // start of a minute bucket
	l := newRTTLimiter(6, func() time.Time { return now })
	for i := 0; i < 6; i++ {
		if !l.allow() {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	now = now.Add(30 * time.Second)
	if l.allow() {
		t.Fatal("call 30s later in the same minute must be refused")
	}
}

// --- route tests ---

type rttBody struct {
	Success bool `json:"success"`
	Data    struct {
		RTT map[string]*int `json:"rtt"`
	} `json:"data"`
}

// routeDeps: host "a" -> 8.8.8.8 and dial 23ms, host "b" -> resolve error.
// dials counts every dial.
func routeDeps(dials *int) rttDeps {
	var mu sync.Mutex
	return rttDeps{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "b" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) (time.Duration, error) {
			mu.Lock()
			*dials++
			mu.Unlock()
			return 23 * time.Millisecond, nil
		},
		own: func() ([]netip.Addr, error) { return nil, nil },
	}
}

// newRTTRouterEnv builds the production router with fake deps and a fixed
// clock (so the limiter never straddles a minute boundary).
func newRTTRouterEnv(t *testing.T, d rttDeps) *testEnv {
	t.Helper()
	oldDeps, oldClock := rttDepsForRouter, rttClock
	rttDepsForRouter = func() rttDeps { return d }
	fixed := time.Unix(1_700_000_040, 0)
	rttClock = func() time.Time { return fixed }
	t.Cleanup(func() { rttDepsForRouter, rttClock = oldDeps, oldClock })
	return setupTestEnv(t)
}

func rttReq(targets ...rttTarget) map[string]any {
	return map[string]any{"targets": targets}
}

func TestRTTRouteReturnsMsAndNull(t *testing.T) {
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	rec := env.authedRequest(t, "POST", "/api/rtt", rttReq(
		rttTarget{ID: "ap-southeast", Host: "a", Port: 443},
		rttTarget{ID: "eu-central", Host: "b", Port: 443},
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body rttBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success {
		t.Error("success must be true")
	}
	if v := body.Data.RTT["ap-southeast"]; v == nil || *v != 23 {
		t.Errorf("ap-southeast = %v, want 23", v)
	}
	if v, ok := body.Data.RTT["eu-central"]; !ok || v != nil {
		t.Errorf("eu-central = %v (present %v), want present and null", v, ok)
	}
}

func TestRTTRouteNullValueIsEncodedAsNull(t *testing.T) {
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	rec := env.authedRequest(t, "POST", "/api/rtt", rttReq(rttTarget{ID: "eu-central", Host: "b", Port: 443}))
	if !strings.Contains(rec.Body.String(), `"eu-central":null`) {
		t.Errorf("body %s lacks \"eu-central\":null", rec.Body.String())
	}
}

func TestRTTRouteWrongKeyIs404(t *testing.T) {
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	rec := env.request(t, "POST", "/api/rtt", rttReq(rttTarget{ID: "a", Host: "a", Port: 443}), "nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if dials != 0 {
		t.Errorf("dials = %d, want 0", dials)
	}
}

func TestRTTRouteDisabledIs404(t *testing.T) {
	t.Setenv("RTT_ENABLED", "0")
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	rec := env.authedRequest(t, "POST", "/api/rtt", rttReq(rttTarget{ID: "a", Host: "a", Port: 443}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	var body rttBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Success {
		t.Errorf("body %s, want success false", rec.Body.String())
	}
	if dials != 0 {
		t.Errorf("dials = %d, want 0", dials)
	}
}

func TestRTTRouteRejectsBadRequests(t *testing.T) {
	ok := rttTarget{ID: "a", Host: "a", Port: 443}
	many := make([]rttTarget, 17)
	for i := range many {
		many[i] = rttTarget{ID: "id" + strings.Repeat("x", i), Host: "a", Port: 443}
	}
	cases := []struct {
		name string
		body any
	}{
		{"no targets", rttReq()},
		{"17 targets", rttReq(many...)},
		{"port 80", rttReq(rttTarget{ID: "a", Host: "a", Port: 80})},
		{"empty id", rttReq(rttTarget{ID: "", Host: "a", Port: 443})},
		{"id of 65 chars", rttReq(rttTarget{ID: strings.Repeat("i", 65), Host: "a", Port: 443})},
		{"empty host", rttReq(rttTarget{ID: "a", Host: "", Port: 443})},
		{"duplicate id", rttReq(ok, rttTarget{ID: "a", Host: "b", Port: 443})},
		{"not json", "this is not an object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dials := 0
			env := newRTTRouterEnv(t, routeDeps(&dials))
			rec := env.authedRequest(t, "POST", "/api/rtt", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if dials != 0 {
				t.Errorf("dials = %d, want 0", dials)
			}
		})
	}
}

func TestRTTRouteBodyOver8KBIs400(t *testing.T) {
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	rec := env.authedRequest(t, "POST", "/api/rtt", rttReq(rttTarget{ID: "a", Host: strings.Repeat("h", 9<<10), Port: 443}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if dials != 0 {
		t.Errorf("dials = %d, want 0", dials)
	}
}

func TestRTTRouteSeventhCallInAMinuteIs429(t *testing.T) {
	dials := 0
	env := newRTTRouterEnv(t, routeDeps(&dials))
	req := rttReq(rttTarget{ID: "a", Host: "a", Port: 443})
	for i := 0; i < 6; i++ {
		if rec := env.authedRequest(t, "POST", "/api/rtt", req); rec.Code != http.StatusOK {
			t.Fatalf("call %d: status %d", i+1, rec.Code)
		}
	}
	rec := env.authedRequest(t, "POST", "/api/rtt", req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("7th call status %d, want 429", rec.Code)
	}
	var body rttBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Success {
		t.Errorf("body %s, want success false", rec.Body.String())
	}
}

func TestRTTRouteOverallDeadlineStillAnswers200(t *testing.T) {
	old := rttRequestTimeout
	rttRequestTimeout = 50 * time.Millisecond
	t.Cleanup(func() { rttRequestTimeout = old })

	d := routeDeps(new(int))
	d.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	env := newRTTRouterEnv(t, d)
	start := time.Now()
	rec := env.authedRequest(t, "POST", "/api/rtt", rttReq(rttTarget{ID: "a", Host: "slow", Port: 443}))
	if time.Since(start) > 5*time.Second {
		t.Error("handler did not honour the overall deadline")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var body rttBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if v, ok := body.Data.RTT["a"]; !ok || v != nil {
		t.Errorf("a = %v (present %v), want present and null", v, ok)
	}
}
