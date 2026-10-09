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

// sendUDP fires a raw PNB text datagram at the given host:port.
func sendUDP(t *testing.T, addr string, data []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sender socket: %v", err)
	}
	defer pc.Close()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	if _, err := pc.WriteTo(data, ua); err != nil {
		t.Fatalf("send to %s: %v", addr, err)
	}
}

const smokeText = "<PNB40200>dnsquery3 1791462429 00-e2-69-13-cd-4e 10.10.10.222 53210 223.5.5.5 53 edr.syslog.top"

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for: %s", msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func listenerPort(t *testing.T, r *Receiver, device string) int {
	t.Helper()
	for i := 0; i < 120; i++ {
		for _, l := range r.Listeners() {
			if l.Device == device && l.Addr != "" {
				_, port, err := net.SplitHostPort(l.Addr)
				if err != nil {
					t.Fatalf("bad addr %s: %v", l.Addr, err)
				}
				var p int
				fmt.Sscanf(port, "%d", &p)
				return p
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("device %s never bound", device)
	return 0
}

// TestMultiDeviceLifecycle exercises the full device registry flow:
//
//	add device  -> listener binds, packets ingested with the device name
//	change port -> listener rebinds
//	disable     -> listener stops
func TestMultiDeviceLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "palog.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	defer st.Close()

	d1, err := st.UpsertDevice(store.Device{Name: "fw-1", Port: freeUDPPort(t), Enabled: true})
	if err != nil {
		t.Fatalf("upsert fw-1: %v", err)
	}

	r := New(st, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	p1 := listenerPort(t, r, "fw-1")
	sendUDP(t, fmt.Sprintf("127.0.0.1:%d", p1), []byte(smokeText))
	waitFor(t, func() bool { return atomic.LoadInt64(&r.Records) >= 1 }, "record from fw-1")
	if got := atomic.LoadInt64(&r.Packets); got != 1 {
		t.Fatalf("packets = %d, want 1", got)
	}
	// verify device name landed in the DB (async batch write: poll until committed)
	var qtotal int64
	var qitems []store.Entry
	waitFor(t, func() bool {
		total, items, err := st.Query(store.LogQuery{Device: "fw-1", Limit: 5})
		if err != nil {
			return false
		}
		qtotal, qitems = total, items
		return total == 1 && len(items) == 1
	}, "fw-1 row committed")
	if qtotal != 1 || len(qitems) != 1 || qitems[0].Device != "fw-1" {
		t.Fatalf("fw-1 rows = %d items=%d first.device=%q, want 1/1/fw-1", qtotal, len(qitems), qitems[0].Device)
	}

	// change port -> rebind
	newPort := freeUDPPort(t)
	d1.Port = newPort
	if _, err := st.UpsertDevice(d1); err != nil {
		t.Fatalf("upsert port change: %v", err)
	}
	waitFor(t, func() bool {
		for _, l := range r.Listeners() {
			if l.Device == "fw-1" && l.Addr != "" {
				_, port, err := net.SplitHostPort(l.Addr)
				if err == nil {
					var p int
					fmt.Sscanf(port, "%d", &p)
					return p == newPort
				}
			}
		}
		return false
	}, "fw-1 rebound to new port")
	p2 := listenerPort(t, r, "fw-1")

	sendUDP(t, fmt.Sprintf("127.0.0.1:%d", p2), []byte(smokeText))
	waitFor(t, func() bool { return atomic.LoadInt64(&r.Records) >= 2 }, "record after rebind")
	if got := atomic.LoadInt64(&r.Packets); got != 2 {
		t.Fatalf("packets after rebind = %d, want 2", got)
	}

	// add a second device
	d2, err := st.UpsertDevice(store.Device{Name: "fw-2", Port: freeUDPPort(t), Enabled: true})
	if err != nil {
		t.Fatalf("upsert fw-2: %v", err)
	}
	p3 := listenerPort(t, r, "fw-2")
	sendUDP(t, fmt.Sprintf("127.0.0.1:%d", p3), []byte(smokeText))
	waitFor(t, func() bool {
		total, _, err := st.Query(store.LogQuery{Device: "fw-2", Limit: 1})
		return err == nil && total == 1
	}, "record from fw-2")
	sendUDP(t, fmt.Sprintf("127.0.0.1:%d", p3), []byte(smokeText))
	waitFor(t, func() bool {
		total, _, err := st.Query(store.LogQuery{Device: "fw-2", Limit: 1})
		return err == nil && total == 2
	}, "fw-2 rows == 2")

	// disable fw-2 -> listener stops
	d2.Enabled = false
	if _, err := st.UpsertDevice(d2); err != nil {
		t.Fatalf("upsert disable: %v", err)
	}
	waitFor(t, func() bool {
		for _, l := range r.Listeners() {
			if l.Device == "fw-2" {
				return false
			}
		}
		return true
	}, "fw-2 listener removed")

	// graceful shutdown
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

// TestNoDevicesStillServes ensures Run works with an empty device registry.
func TestNoDevicesStillServes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "palog.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	defer st.Close()

	r := New(st, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(1200 * time.Millisecond) // > reconcile interval
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}