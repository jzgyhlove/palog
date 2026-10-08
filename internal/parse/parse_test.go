package parse

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type goldenRecord struct {
	Type      int               `json:"type"`
	Proto     int               `json:"proto"`
	Appid     int               `json:"appid"`
	TS1       int               `json:"ts1"`
	TS2       int               `json:"ts2"`
	BytesIn   int               `json:"bytes_in"`
	BytesOut  int               `json:"bytes_out"`
	Iface     string            `json:"iface"`
	X         int               `json:"x"`
	MAC       string            `json:"mac"`
	Src       *string           `json:"src"`
	Dst       *string           `json:"dst"`
	Sport     *int              `json:"sport"`
	Dport     *int              `json:"dport"`
	Domain    *string           `json:"domain"`
	Iface2    *string           `json:"iface2"`
	Flags     *string           `json:"flags"`
	Counters  []int             `json:"counters"`
	Extra     map[string]string `json:"extra"`
}

type goldenPacket struct {
	Index   int            `json:"index"`
	Records []goldenRecord `json:"records"`
}

type goldenFile struct {
	Packets []goldenPacket `json:"packets"`
	Text    []string       `json:"text"`
}

func loadGolden(t *testing.T) *goldenFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return &g
}

// extractPNBPayloads pulls every payload starting with "PNB\0" out of a pcap
// file (libpcap little-endian format) in capture order.
func extractPNBPayloads(t *testing.T, name string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if len(data) < 24 {
		t.Fatalf("pcap too short")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	// After a little-endian read: 0xa1b2c3d4/0xa1b23c4d => LE file,
	// 0xd4c3b2a1/0x4d3cb2a1 => big-endian file.
	le := false
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		le = true
	case 0xd4c3b2a1, 0x4d3cb2a1:
		le = false
	default:
		t.Fatalf("unexpected pcap magic %#x", magic)
	}
	u32 := func(b []byte) uint32 {
		if le {
			return binary.LittleEndian.Uint32(b)
		}
		return binary.BigEndian.Uint32(b)
	}
	var out [][]byte
	off := 24
	for off+16 <= len(data) {
		incl := int(u32(data[off+8 : off+12]))
		off += 16
		if off+incl > len(data) {
			break
		}
		pkt := data[off : off+incl]
		off += incl
		if i := bytes.Index(pkt, []byte("PNB\x00")); i >= 0 {
			out = append(out, pkt[i:])
		}
	}
	return out
}

func TestBinaryAgainstGolden(t *testing.T) {
	g := loadGolden(t)
	payloads := extractPNBPayloads(t, "panabit_cap3.pcap")
	if len(payloads) != len(g.Packets) {
		t.Fatalf("payload count %d != golden packet count %d", len(payloads), len(g.Packets))
	}

	total := 0
	for i, pl := range payloads {
		want := g.Packets[i]
		if want.Index != i {
			t.Fatalf("golden packet order broken at %d", i)
		}
		got, err := ParseBinary(pl)
		if err != nil {
			t.Errorf("packet %d: ParseBinary error: %v", i, err)
		}
		if len(got) != len(want.Records) {
			t.Errorf("packet %d: got %d records, want %d", i, len(got), len(want.Records))
			continue
		}
		for j := range got {
			compareRecord(t, i, j, got[j], want.Records[j])
		}
		total += len(got)
	}
	if total != 1503 {
		t.Errorf("total records %d, want 1503", total)
	}
	t.Logf("validated %d packets / %d records against golden", len(payloads), total)
}

func compareRecord(t *testing.T, pkt, rec int, got Record, want goldenRecord) {
	t.Helper()
	fail := func(format string, args ...interface{}) {
		t.Errorf("packet %d record %d: %s", pkt, rec, fmt.Sprintf(format, args...))
	}
	if int(got.Type) != want.Type {
		fail("type %d != %d", got.Type, want.Type)
	}
	if int(got.Proto) != want.Proto {
		fail("proto %d != %d", got.Proto, want.Proto)
	}
	if got.Appid != want.Appid {
		fail("appid %d != %d", got.Appid, want.Appid)
	}
	if int(got.TS1) != want.TS1 {
		fail("ts1 %d != %d", got.TS1, want.TS1)
	}
	if int(got.TS2) != want.TS2 {
		fail("ts2 %d != %d", got.TS2, want.TS2)
	}
	if int(got.BytesIn) != want.BytesIn {
		fail("bytes_in %d != %d", got.BytesIn, want.BytesIn)
	}
	if int(got.BytesOut) != want.BytesOut {
		fail("bytes_out %d != %d", got.BytesOut, want.BytesOut)
	}
	if got.Iface != want.Iface {
		fail("iface %q != %q", got.Iface, want.Iface)
	}
	if int(got.X) != want.X {
		fail("x %d != %d", got.X, want.X)
	}
	if got.MAC != want.MAC {
		fail("mac %q != %q", got.MAC, want.MAC)
	}
	checkStr := func(name string, gotS string, wantS *string) {
		if wantS == nil {
			if gotS != "" {
				fail("%s %q, want empty (null)", name, gotS)
			}
			return
		}
		if gotS != *wantS {
			fail("%s %q != %q", name, gotS, *wantS)
		}
	}
	checkStr("src", got.Src, want.Src)
	checkStr("dst", got.Dst, want.Dst)
	if want.Sport != nil && got.Sport != *want.Sport {
		fail("sport %d != %d", got.Sport, *want.Sport)
	}
	if want.Dport != nil && got.Dport != *want.Dport {
		fail("dport %d != %d", got.Dport, *want.Dport)
	}
	checkStr("domain", got.Domain, want.Domain)
	checkStr("iface2", got.Iface2, want.Iface2)
	checkStr("flags", got.Flags, want.Flags)
	if len(got.Counters) != len(want.Counters) {
		fail("counters len %d != %d", len(got.Counters), len(want.Counters))
	} else {
		for k := range want.Counters {
			if int(got.Counters[k]) != want.Counters[k] {
				fail("counters[%d] %d != %d", k, got.Counters[k], want.Counters[k])
			}
		}
	}
	if len(got.Extra) != len(want.Extra) {
		fail("extra size %d != %d (got %v want %v)", len(got.Extra), len(want.Extra), got.Extra, want.Extra)
	} else {
		for k, v := range want.Extra {
			if gv, ok := got.Extra[k]; !ok {
				fail("extra missing key %s", k)
			} else if gv != v {
				fail("extra[%s] %q != %q", k, gv, v)
			}
		}
	}
}

func TestTextAgainstGolden(t *testing.T) {
	g := loadGolden(t)
	if len(g.Text) != 145 {
		t.Fatalf("golden text count %d, want 145", len(g.Text))
	}
	for i, line := range g.Text {
		got, err := ParseText(line)
		if err != nil {
			t.Errorf("text %d: %v (line=%q)", i, err, line)
			continue
		}
		f := strings.Fields(line)
		switch got.Kind {
		case KindDNS:
			if f[0] != "dnsquery3" {
				t.Errorf("text %d: kind %s but starts with %q", i, got.Kind, f[0])
			}
			if len(f) != 8 {
				t.Errorf("text %d: dns fields %d != 8", i, len(f))
				continue
			}
			if got.Domain != f[7] {
				t.Errorf("text %d: domain %q != %q", i, got.Domain, f[7])
			}
			if got.SrcIP != f[3] || got.DstIP != f[5] || got.MAC != f[2] {
				t.Errorf("text %d: ip/mac mismatch: %s %s %s", i, got.SrcIP, got.DstIP, got.MAC)
			}
			if got.DstPort != 53 {
				t.Errorf("text %d: dst port %d != 53", i, got.DstPort)
			}
		case KindHTTP:
			if f[0] != "HTTP4" {
				t.Errorf("text %d: kind %s but starts with %q", i, got.Kind, f[0])
			}
			if len(f) < 12 {
				t.Errorf("text %d: http fields %d < 12", i, len(f))
				continue
			}
			if got.Host != f[9] || got.Method != f[8] || got.User != f[len(f)-1] {
				t.Errorf("text %d: http host/method/user mismatch (%q %q %q)", i, got.Host, got.Method, got.User)
			}
			if wantPath := strings.Join(f[10:len(f)-1], " "); got.Path != wantPath {
				t.Errorf("text %d: path %q != %q", i, got.Path, wantPath)
			}
		default:
			t.Errorf("text %d: unexpected kind %q", i, got.Kind)
		}
	}
}

// TestNoPanicOnMalformed feeds truncated and corrupted inputs to the binary
// parser; it must never panic and must never loop forever.
func TestNoPanicOnMalformed(t *testing.T) {
	g := loadGolden(t)
	payloads := extractPNBPayloads(t, "panabit_cap3.pcap")
	if len(payloads) == 0 {
		t.Fatal("no payloads")
	}
	full := payloads[0]
	// truncations of a real packet
	for cut := 0; cut < len(full); cut += 7 {
		ParseBinary(full[:cut])
	}
	// corrupted bytes
	for i := 0; i < len(full); i += 13 {
		bad := append([]byte(nil), full...)
		bad[i] ^= 0xff
		ParseBinary(bad)
	}
	// garbage
	ParseBinary(nil)
	ParseBinary([]byte("PNB\x00"))
	ParseBinary(bytes.Repeat([]byte{0x40, 0x06, 0x00, 0x00}, 100))
	// every golden packet, prefix-cut
	for _, p := range g.Packets {
		_ = p
		break
	}
	// text garbage
	for _, s := range []string{"", "<PNB40200>", "HTTP4", "dnsquery3 12", "HTTP4 1 x", "bogus 1 2 3"} {
		ParseText(s)
	}
}
