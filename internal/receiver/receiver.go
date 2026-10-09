// Package receiver listens for Panabit PNB logs over UDP — one listener per
// configured device/port — parses them, and hands normalized entries to the
// store. Device changes (add/rename/report/disable) are reconciled every
// second from the device registry.
package receiver

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
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

// Listener is one live UDP device listener (for the health endpoint).
type Listener struct {
	Device string `json:"device"`
	Port   int    `json:"port"`
	Addr   string `json:"addr"`
	Active bool   `json:"active"`
}

// Receiver owns the per-device UDP sockets, the parse pipeline and the batch
// writer. Device registry comes from the store; Run reconciles every second.
type Receiver struct {
	store *store.Store
	ch    chan []store.Entry

	Packets     int64
	Records     int64
	ParseErrors int64
	Dropped     int64

	mu        sync.Mutex
	listeners map[string]*deviceListener // keyed by device name

	doneCh chan struct{}
}

// deviceListener is one named UDP socket.
type deviceListener struct {
	dev    store.Device
	conn   net.PacketConn
	cancel chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

// New creates a Receiver with a batch channel of chSize.
func New(s *store.Store, chSize int) *Receiver {
	return &Receiver{
		store:     s,
		ch:        make(chan []store.Entry, chSize),
		listeners: map[string]*deviceListener{},
		doneCh:    make(chan struct{}),
	}
}

// Done is closed once Run has fully drained and returned.
func (r *Receiver) Done() <-chan struct{} { return r.doneCh }

// Listeners snapshots the current live listeners.
func (r *Receiver) Listeners() []Listener {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Listener, 0, len(r.listeners))
	for _, dl := range r.listeners {
		l := Listener{Device: dl.dev.Name, Port: dl.dev.Port, Active: true}
		if dl.conn != nil {
			l.Addr = dl.conn.LocalAddr().String()
		}
		out = append(out, l)
	}
	return out
}

// Run blocks until ctx is done, reconciling device listeners every second.
func (r *Receiver) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.writerLoop(ctx) }()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	r.reconcile() // initial pass

	for {
		select {
		case <-ctx.Done():
			r.mu.Lock()
			for _, dl := range r.listeners {
				dl.close()
			}
			ls := make([]*deviceListener, 0, len(r.listeners))
			for _, dl := range r.listeners {
				ls = append(ls, dl)
			}
			r.listeners = map[string]*deviceListener{}
			r.mu.Unlock()
			for _, dl := range ls {
				dl.wg.Wait()
			}
			close(r.ch)
			wg.Wait()
			close(r.doneCh)
			return nil
		case <-ticker.C:
			r.reconcile()
		}
	}
}

// reconcile diffs desired devices (from the store) against live listeners.
func (r *Receiver) reconcile() {
	desired, err := r.store.ListEnabledDevices()
	if err != nil {
		slog.Error("reconcile devices", "err", err)
		return
	}
	want := map[string]store.Device{}
	for _, d := range desired {
		want[d.Name] = d
	}

	r.mu.Lock()
	// Stop listeners whose device was removed, disabled or re-pointed.
	toStop := []*deviceListener{}
	for name, dl := range r.listeners {
		d, ok := want[name]
		if !ok || d.Port != dl.dev.Port || d.ID != dl.dev.ID {
			toStop = append(toStop, dl)
			delete(r.listeners, name)
		}
	}
	// Start missing listeners.
	toStart := []store.Device{}
	for _, d := range desired {
		if _, ok := r.listeners[d.Name]; !ok {
			toStart = append(toStart, d)
		}
	}
	r.mu.Unlock()

	for _, dl := range toStop {
		dl.close()
		dl.wg.Wait()
		slog.Info("udp stopped", "device", dl.dev.Name, "port", dl.dev.Port)
	}
	for _, d := range toStart {
		r.startListener(d)
	}
}

// startListener opens a socket for d and spawns its reader. Errors are logged;
// the next reconcile retries.
func (r *Receiver) startListener(d store.Device) {
	pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(d.Port))
	if err != nil {
		slog.Error("udp listen", "device", d.Name, "port", d.Port, "err", err)
		return
	}
	dl := &deviceListener{
		dev:    d,
		conn:   pc,
		cancel: make(chan struct{}),
	}
	r.mu.Lock()
	r.listeners[d.Name] = dl
	r.mu.Unlock()
	dl.wg.Add(1)
	go func() { defer dl.wg.Done(); r.readLoop(dl) }()
	slog.Info("udp listening", "device", d.Name, "addr", pc.LocalAddr().String())
}

func (dl *deviceListener) close() {
	dl.once.Do(func() { close(dl.cancel) })
	if dl.conn != nil {
		dl.conn.Close()
	}
}

func (r *Receiver) readLoop(dl *deviceListener) {
	buf := make([]byte, udpBufSize)
	conn := dl.conn
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-dl.cancel:
				return // expected shutdown
			default:
			}
			// transient error; retry after a short pause (do not busy-loop)
			slog.Error("udp read", "device", dl.dev.Name, "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		r.handlePacket(dl.dev.Name, buf[:n])
	}
}

func (r *Receiver) handlePacket(device string, data []byte) {
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
		for i := range entries {
			entries[i].Device = device
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
		for i := range entries {
			entries[i].Device = device
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
				case e, ok := <-r.ch:
					if !ok {
						// channel closed by Run: all queued entries are drained
						flush()
						return
					}
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
	return store.Entry{
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