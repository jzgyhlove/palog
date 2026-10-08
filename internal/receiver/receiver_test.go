package receiver

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"palog/internal/store"
)

func TestAddrEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{":40200", "[::]:40200", true},
		{":40200", "0.0.0.0:40200", true},
		{"[::]:40200", "0.0.0.0:40200", true},
		{":40200", "127.0.0.1:40200", false},
		{":40200", ":40201", false},
		{"127.0.0.1:40200", "127.0.0.1:40200", true},
		{"[::1]:5000", "[::1]:5000", true},
	}
	for _, c := range cases {
		if got := addrEqual(c.a, c.b); got != c.want {
			t.Errorf("addrEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// freeUDPPort grabs a free UDP port, then releases it so the receiver can bind it.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// sendUDP fires a raw PNB text datagram at addr.
func sendUDP(t *testing.T, addr string, data []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sender socket: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo(data, mustUDPAddr(t, addr)); err != nil {
		t.Fatalf("send to %s: %v", addr, err)
	}
}

func mustUDPAddr(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	return ua
}

const smokeText = "<PNB40200>dnsquery3 1791462429 00-e2-69-13-cd-4e 10.10.10.222 53210 223.5.5.5 53 edr.syslog.top"

// TestReceiverLifecycle verifies:
//   - packets/records counters advance while reading,
//   - SetAddr (rebind) moves the socket and the reader keeps consuming afterwards,
//   - shutdown via ctx drains and closes Done().
func TestReceiverLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "palog.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	defer st.Close()

	port := freeUDPPort(t)
	r := New(st, fmt.Sprintf("127.0.0.1:%d", port), 64)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// Wait for the socket to come up.
	deadline := time.Now().Add(3 * time.Second)
	for r.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("receiver socket did not come up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	first := r.Addr()
	t.Logf("initial addr: %s", first)

	sendUDP(t, first, []byte(smokeText))
	waitFor(t, func() bool { return count(&r.Packets) >= 1 }, "first packet received")
	if r.Records != 1 {
		t.Fatalf("records after 1 text line = %d, want 1", r.Records)
	}

	// Rebind to a new port; the wildcard-equal path and the reader restart path
	// are both exercised (ports differ, reader must be respawned).
	newPort := freeUDPPort(t)
	r.SetAddr(fmt.Sprintf("127.0.0.1:%d", newPort))

	deadline = time.Now().Add(5 * time.Second)
	for r.Addr() == first {
		if time.Now().After(deadline) {
			t.Fatalf("addr did not change after SetAddr; still %s", first)
		}
		time.Sleep(50 * time.Millisecond)
	}
	second := r.Addr()
	t.Logf("rebound addr: %s", second)
	if second == first {
		t.Fatal("rebind kept the same socket")
	}

	// Old socket must be closed: sending there is a no-op for our counters.
	sendUDP(t, first, []byte(smokeText))
	time.Sleep(300 * time.Millisecond)
	if r.Packets != 1 {
		t.Errorf("packets after stale-port send = %d, want 1 (old socket must be closed)", r.Packets)
	}

	// New socket keeps consuming — this is the regression the old code failed.
	sendUDP(t, second, []byte(smokeText))
	waitFor(t, func() bool { return count(&r.Packets) >= 2 }, "packet on rebound socket")
	if r.Records != 2 {
		t.Errorf("records after rebind = %d, want 2", r.Records)
	}

	// Graceful shutdown.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	select {
	case <-r.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() not closed after Run returned")
	}
}

func count(p *int64) int64 {
	return atomic.LoadInt64(p)
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for: %s", msg)
		}
		time.Sleep(20 * time.Millisecond)
	}
}