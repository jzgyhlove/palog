// Package parse implements the Panabit PNB log protocol parsers
// (text lines + binary session records). See docs/PROTOCOL.md.
package parse

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Text logs: <PNB{port}>dnsquery3 ... / <PNB{port}>HTTP4 ...
// ---------------------------------------------------------------------------

// TextKind values stored in the `kind` column.
const (
	KindDNS    = "dnsquery"
	KindHTTP   = "http"
	KindSess   = "session"
)

// TextLog is a normalized text log line.
type TextLog struct {
	Kind    string // dnsquery | http
	Epoch   uint32
	MAC     string
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
	Appid   int  // HTTP only, -1 otherwise
	Method  string
	Host    string
	Path    string
	User    string
	Domain  string // dnsquery only
	Raw     string
}

// stripPrefix removes a leading "<PNBnnnn>" syslog-style prefix if present.
func stripPrefix(line string) string {
	if strings.HasPrefix(line, "<PNB") {
		if i := strings.IndexByte(line, '>'); i >= 0 {
			return line[i+1:]
		}
	}
	return line
}

// ParseText parses one text log line (with or without <PNBxxxx> prefix).
func ParseText(line string) (TextLog, error) {
	raw := strings.TrimSpace(line)
	f := strings.Fields(strings.TrimSpace(stripPrefix(raw)))
	if len(f) < 2 {
		return TextLog{}, fmt.Errorf("too few fields: %d", len(f))
	}
	t := TextLog{Raw: raw, Appid: -1}

	epoch, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return TextLog{}, fmt.Errorf("bad epoch %q: %w", f[1], err)
	}
	t.Epoch = uint32(epoch)

	switch f[0] {
	case "dnsquery3":
		if len(f) != 8 {
			return TextLog{}, fmt.Errorf("dnsquery3: want 8 fields, got %d", len(f))
		}
		t.Kind = KindDNS
		t.MAC = f[2]
		t.SrcIP = f[3]
		if net.ParseIP(t.SrcIP) == nil {
			return TextLog{}, fmt.Errorf("bad src ip %q", t.SrcIP)
		}
		p, err := strconv.Atoi(f[4])
		if err != nil {
			return TextLog{}, fmt.Errorf("bad src port %q", f[4])
		}
		t.SrcPort = p
		t.DstIP = f[5]
		if net.ParseIP(t.DstIP) == nil {
			return TextLog{}, fmt.Errorf("bad dst ip %q", t.DstIP)
		}
		if f[6] != "53" {
			return TextLog{}, fmt.Errorf("bad dns port %q", f[6])
		}
		t.DstPort = 53
		t.Domain = f[7]
	case "HTTP4":
		if len(f) < 12 {
			return TextLog{}, fmt.Errorf("HTTP4: want >=12 fields, got %d", len(f))
		}
		t.Kind = KindHTTP
		t.MAC = f[2]
		t.SrcIP = f[3]
		if net.ParseIP(t.SrcIP) == nil {
			return TextLog{}, fmt.Errorf("bad src ip %q", t.SrcIP)
		}
		p, err := strconv.Atoi(f[4])
		if err != nil {
			return TextLog{}, fmt.Errorf("bad src port %q", f[4])
		}
		t.SrcPort = p
		t.DstIP = f[5]
		if net.ParseIP(t.DstIP) == nil {
			return TextLog{}, fmt.Errorf("bad dst ip %q", t.DstIP)
		}
		dp, err := strconv.Atoi(f[6])
		if err != nil {
			return TextLog{}, fmt.Errorf("bad dst port %q", f[6])
		}
		t.DstPort = dp
		ap, err := strconv.Atoi(f[7])
		if err != nil {
			return TextLog{}, fmt.Errorf("bad appid %q", f[7])
		}
		t.Appid = ap
		t.Method = f[8]
		t.Host = f[9]
		t.Path = strings.Join(f[10:len(f)-1], " ")
		t.User = f[len(f)-1]
	default:
		return TextLog{}, fmt.Errorf("unknown line kind %q", f[0])
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Binary session-record packets
// ---------------------------------------------------------------------------

// Record is one decoded binary session record.
type Record struct {
	Type      uint8
	Proto     uint8
	Appid     int
	TS1       uint32
	TS2       uint32
	BytesIn   uint32
	BytesOut  uint32
	Iface     string
	X         uint8
	MAC       string
	Src       string
	Dst       string
	Sport     int
	Dport     int
	Domain    string
	Iface2    string
	Flags     string
	Counters  []uint32
	Extra     map[string]string
	HasTuple  bool
	HasIface2 bool
	HasFlags  bool
}

const (
	hdrLen       = 20
	recHdrLen    = 4
	recFixedLen  = 16 // ts1 ts2 bytesIn bytesOut
	tsWindowBack = 259200
	tsWindowFwd  = 3600
)

// isHeader reports whether b[off:] starts a valid record header,
// given packet timestamp t0 (seconds).
func isHeader(b []byte, off, t0 int) bool {
	if off+recHdrLen+recFixedLen > len(b) {
		return false
	}
	proto := b[off+1]
	if proto != 6 && proto != 17 {
		return false
	}
	tp := b[off]
	if tp < 0x40 || tp > 0x7c || tp%4 != 0 {
		return false
	}
	ts1 := int(binary.LittleEndian.Uint32(b[off+4:]))
	return ts1 >= t0-tsWindowBack && ts1 <= t0+tsWindowFwd
}

// ParseBinary decodes a whole PNB binary packet (payload beginning with "PNB\0").
// It returns every record decoded so far plus the first structural error, if any.
// It never panics on malformed input.
func ParseBinary(buf []byte) ([]Record, error) {
	if len(buf) < hdrLen || string(buf[0:4]) != "PNB\x00" {
		return nil, fmt.Errorf("bad magic or truncated header")
	}
	t0 := int(binary.LittleEndian.Uint32(buf[12:16]))
	off := hdrLen
	var recs []Record

	for off < len(buf) {
		if !isHeader(buf, off, t0) {
			break
		}
		rec := Record{
			Type:  buf[off],
			Proto: buf[off+1],
			Appid: int(binary.LittleEndian.Uint16(buf[off+2 : off+4])),
		}
		off += recHdrLen

		rec.TS1 = binary.LittleEndian.Uint32(buf[off:])
		rec.TS2 = binary.LittleEndian.Uint32(buf[off+4:])
		rec.BytesIn = binary.LittleEndian.Uint32(buf[off+8:])
		rec.BytesOut = binary.LittleEndian.Uint32(buf[off+12:])
		off += recFixedLen

		z := -1
		for i := off; i < len(buf); i++ {
			if buf[i] == 0 {
				z = i
				break
			}
		}
		if z < 0 || z-off > 64 {
			return recs, fmt.Errorf("unterminated iface at offset %d", off)
		}
		rec.Iface = string(buf[off:z])
		off = z + 1

		if off+7 > len(buf) {
			return recs, fmt.Errorf("truncated x+mac at offset %d", off)
		}
		rec.X = buf[off]
		rec.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			buf[off+1], buf[off+2], buf[off+3], buf[off+4], buf[off+5], buf[off+6])
		off += 7

		// TLV stream until 0x00 terminator (or an out-of-band next header).
		for off < len(buf) {
			t := buf[off]
			if t == 0 {
				off++
				break
			}
			if isHeader(buf, off, t0) {
				break // missing terminator
			}
			if off+2 > len(buf) {
				return recs, fmt.Errorf("truncated TLV length at %d", off)
			}
			ln := int(buf[off+1])
			voff := off + 2
			if voff+ln > len(buf) {
				return recs, fmt.Errorf("truncated TLV value at %d", off)
			}
			val := buf[voff : voff+ln]
			switch {
			case t == 0x01 && ln == 12:
				rec.Src = net.IP(val[0:4]).String()
				rec.Dst = net.IP(val[4:8]).String()
				rec.Sport = int(binary.BigEndian.Uint16(val[8:10]))
				rec.Dport = int(binary.BigEndian.Uint16(val[10:12]))
				rec.HasTuple = true
			case t == 0x03:
				rec.Domain = nulStr(val)
			case t == 0x05 && ln == 16:
				rec.Counters = []uint32{
					binary.LittleEndian.Uint32(val[0:4]),
					binary.LittleEndian.Uint32(val[4:8]),
					binary.LittleEndian.Uint32(val[8:12]),
					binary.LittleEndian.Uint32(val[12:16]),
				}
			case t == 0x1e:
				rec.Iface2 = nulStr(val)
				rec.HasIface2 = true
			case (t == 0x08 || t == 0x14) && ln == 2:
				rec.Flags = fmt.Sprintf("%02x%02x", val[0], val[1])
				rec.HasFlags = true
			default:
				if rec.Extra == nil {
					rec.Extra = map[string]string{}
				}
				rec.Extra[fmt.Sprintf("%#x", t)] = fmt.Sprintf("%x", val)
			}
			off = voff + ln
		}
		recs = append(recs, rec)

		// Gap scan: next record header is always 4-aligned; skip filler bytes.
		for off < len(buf) && !isHeader(buf, off, t0) {
			off++
		}
	}
	return recs, nil
}

func nulStr(v []byte) string {
	if i := indexByte(v, 0); i >= 0 {
		return string(v[:i])
	}
	return string(v)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
