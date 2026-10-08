// Package receiver listens for Panabit PNB logs over UDP, parses them, and
// hands normalized entries to the store.
package receiver

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"palog/internal/parse"
	"palog/internal/store"
)

const (
	udpBufSize = 65536
	batchSize  = 100
	batchEvery = 200 * time.Millisecond
)

// Receiver owns the UDP socket, the parse pipeline and the batch writer.
type Receiver struct {
	store   *store.Store
	newAddr string // address to (re)bind on next rebuild pass
	conn    net.PacketConn
	ch      chan []store.Entry

	Packets     int64
	Records     int64
	ParseErrors int64
	Dropped     int64

	mu   sync.Mutex
	done bool

	doneCh chan struct{}
}

// New creates a Receiver bound to newAddr. Call Run to start, SetAddr to hot-rebind.
func New(s *store.Store, addr string, chSize int) *Receiver {
	return &Receiver{
		store:   s,
		newAddr: addr,
		ch:      make(chan []store.Entry, chSize),
		doneCh:  make(chan struct{}),
	}
}

// Done is closed once Run has fully drained and returned.
func (r *Receiver) Done() <-chan struct{} { return r.doneCh }

// Addr returns the currently bound listen address.
func (r *Receiver) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return ""
	}
	return r.conn.LocalAddr().String()
}

// SetAddr requests a rebind to addr on the next rebuild pass.
func (r *Receiver) SetAddr(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.newAddr = addr
}

// addrEqual reports whether two listen addresses are semantically identical:
// ":40200", "[::]:40200" and "0.0.0.0:40200" all count as the same wildcard.
func addrEqual(a, b string) bool {
	ua, errA := net.ResolveUDPAddr("udp", a)
	ub, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil {
		return a == b
	}
	ipEq := ua.IP.Equal(ub.IP)
	if (ua.IP == nil || ua.IP.IsUnspecified()) && (ub.IP == nil || ub.IP.IsUnspecified()) {
		ipEq = true
	}
	return ipEq && ua.Port == ub.Port
}

// Run blocks: it serves the UDP socket and the batch writer until ctx is done.
// The socket is rebound automatically when SetAddr changed the requested address.
func (r *Receiver) Run(ctx context.Context) error {
	r.mu.Lock()
	pc, err := net.ListenPacket("udp", r.newAddr)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.conn = pc
	slog.Info("udp listening", "addr", pc.LocalAddr().String())
	r.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.writerLoop(ctx) }()

	active := pc
	wg.Add(1)
	go func() { defer wg.Done(); r.readLoop(ctx, active) }()

	for {
		select {
		case <-ctx.Done():
			r.mu.Lock()
			r.done = true
			r.mu.Unlock()
			pc.Close()
			close(r.ch)
			wg.Wait()
			close(r.doneCh)
			return nil
		case <-time.After(time.Second):
		}
		r.mu.Lock()
		want := r.newAddr
		cur := r.conn
		r.mu.Unlock()
		if cur != nil && addrEqual(cur.LocalAddr().String(), want) {
			continue
		}
		// Rebind: open new socket first, then swap so readers see the change.
		npc, err := net.ListenPacket("udp", want)
		if err != nil {
			slog.Error("rebind udp", "addr", want, "err", err)
			continue
		}
		r.mu.Lock()
		old := r.conn
		r.conn = npc
		r.mu.Unlock()
		if old != nil {
			old.Close() // unblocks the old reader; it exits on conn mismatch
		}
		pc = npc
		active = npc
		slog.Info("udp re-listening", "addr", npc.LocalAddr().String())
		wg.Add(1)
		go func() { defer wg.Done(); r.readLoop(ctx, npc) }()
	}
}

// readerLoop reads datagrams from conn until it is closed, replaced, or ctx ends.
func (r *Receiver) readLoop(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, udpBufSize)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			r.mu.Lock()
			cur := r.conn
			done := r.done
			r.mu.Unlock()
			if done || cur != conn {
				return // replaced or shutting down; supervisor handles new reader
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			slog.Error("udp read", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		r.handlePacket(buf[:n])
	}
}

func (r *Receiver) handlePacket(data []byte) {
	if bytes.HasPrefix(data, []byte("PNB\x00")) {
		recs, perr := parse.ParseBinary(data)
		atomic.AddInt64(&r.Packets, 1)
		if perr != nil {
			atomic.AddInt64(&r.ParseErrors, 1)
		}
		if len(recs) == 0 {
			return
		}
		entries := make([]store.Entry, 0, len(recs))
		for _, rc := range recs {
			entries = append(entries, entryFromRecord(rc))
		}
		atomic.AddInt64(&r.Records, int64(len(entries)))
		r.enqueue(entries)
		return
	}
	if bytes.HasPrefix(data, []byte("<PNB")) {
		atomic.AddInt64(&r.Packets, 1)
		var entries []store.Entry
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			line = bytes.TrimRight(line, "\r")
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			tl, terr := parse.ParseText(string(line))
			if terr != nil {
				atomic.AddInt64(&r.ParseErrors, 1)
				continue
			}
			entries = append(entries, entryFromText(tl))
		}
		if len(entries) == 0 {
			return
		}
		atomic.AddInt64(&r.Records, int64(len(entries)))
		r.enqueue(entries)
		return
	}
	// Unknown packet kind — count as one parse error.
	atomic.AddInt64(&r.Packets, 1)
	atomic.AddInt64(&r.ParseErrors, 1)
}

// writerLoop drains r.ch into the store in small batched transactions.
func (r *Receiver) writerLoop(ctx context.Context) {
	var pending []store.Entry
	flush := func() {
		if len(pending) == 0 {
			return
		}
		if err := r.store.InsertBatch(pending); err != nil {
			slog.Error("insert batch", "err", err)
			atomic.AddInt64(&r.Dropped, int64(len(pending)))
		}
		pending = pending[:0]
	}
	ticker := time.NewTicker(batchEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case e := <-r.ch:
					pending = append(pending, e...)
				default:
					flush()
					return
				}
			}
		case <-ticker.C:
			flush()
		case e := <-r.ch:
			pending = append(pending, e...)
			if len(pending) >= batchSize {
				flush()
			}
		}
	}
}

func (r *Receiver) enqueue(entries []store.Entry) {
	select {
	case r.ch <- entries:
	default:
		atomic.AddInt64(&r.Dropped, int64(len(entries)))
	}
}

// ---------------------------------------------------------------------------

func entryFromRecord(rc parse.Record) store.Entry {
	e := store.Entry{
		RecvTS:   time.Now().Unix(),
		Kind:     parse.KindSess,
		TS:       int64(rc.TS1),
		TSEnd:    int64(rc.TS2),
		SrcIP:    rc.Src,
		SrcPort:  rc.Sport,
		DstIP:    rc.Dst,
		DstPort:  rc.Dport,
		Proto:    int(rc.Proto),
		MAC:      rc.MAC,
		Iface:    rc.Iface,
		Iface2:   rc.Iface2,
		Appid:    rc.Appid,
		Domain:   rc.Domain,
		BytesIn:  int64(rc.BytesIn),
		BytesOut: int64(rc.BytesOut),
		Counters: rc.Counters,
		Flags:    rc.Flags,
		RecType:  int(rc.Type),
		Extra:    rc.Extra,
	}
	return e
}

func entryFromText(tl parse.TextLog) store.Entry {
	e := store.Entry{
		RecvTS:  time.Now().Unix(),
		Kind:    tl.Kind,
		TS:      int64(tl.Epoch),
		SrcIP:   tl.SrcIP,
		SrcPort: tl.SrcPort,
		DstIP:   tl.DstIP,
		DstPort: tl.DstPort,
		MAC:     tl.MAC,
		Appid:   tl.Appid,
		Domain:  tl.Domain,
		Host:    tl.Host,
		Path:    tl.Path,
		Method:  tl.Method,
		User:    tl.User,
		Raw:     tl.Raw,
	}
	if tl.Kind == parse.KindDNS {
		e.Proto = 17
	} else {
		e.Proto = 6
	}
	return e
}