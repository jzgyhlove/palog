// diag_pcap reads a libpcap capture and classifies every UDP payload against
// the palog parsers, reporting which lines/packets fail and why.
//
// Usage: go run ./tools/diag_pcap <file.pcap> [dport]
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"palog/internal/parse"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: diag_pcap <file.pcap> [dport]")
		os.Exit(2)
	}
	dport := 0
	if len(os.Args) > 2 {
		dport, _ = strconv.Atoi(os.Args[2])
	}
	pkts, err := readPcap(os.Args[1])
	if err != nil {
		fmt.Println("read pcap:", err)
		os.Exit(1)
	}
	fmt.Printf("packets (matching dport=%d): %d\n", dport, len(pkts))

	var binOK, binFail, txtOK, txtFail, notPNB int
	var binErrs, txtErrs []string
	binErrCount := map[string]int{}
	txtErrCount := map[string]int{}
	unknownSamples := []string{}

	for _, p := range pkts {
		if dport != 0 && p.dport != dport {
			continue
		}
		switch {
		case strings.HasPrefix(string(p.payload), "PNB\x00"):
			recs, perr := parse.ParseBinary(p.payload)
			if perr != nil {
				binFail++
				binErrCount[perr.Error()]++
				if len(binErrs) < 5 {
					binErrs = append(binErrs, perr.Error())
				}
			} else if len(recs) > 0 {
				binOK++
			} else {
				binOK++ // header-only / keepalive
			}
		case strings.HasPrefix(string(p.payload), "<PNB"):
			for _, ln := range strings.Split(string(p.payload), "\n") {
				ln = strings.TrimRight(ln, "\r")
				if strings.TrimSpace(ln) == "" {
					continue
				}
				if _, perr := parse.ParseText(ln); perr != nil {
					txtFail++
					// aggregate by first word
					w := firstWord(ln)
					txtErrCount[w]++
					if len(txtErrs) < 10 {
						txtErrs = append(txtErrs, ln)
					}
				} else {
					txtOK++
				}
			}
		default:
			notPNB++
			if len(unknownSamples) < 5 {
				unknownSamples = append(unknownSamples, string(p.payload))
			}
		}
	}
	fmt.Printf("binary ok=%d fail=%d | text ok=%d fail=%d | not-PNB=%d\n",
		binOK, binFail, txtOK, txtFail, notPNB)

	if len(binErrCount) > 0 {
		fmt.Println("\n-- binary parse errors (by message) --")
		keys := sortedKeys(binErrCount)
		for _, k := range keys {
			fmt.Printf("  %4d  %s\n", binErrCount[k], k)
		}
	}
	if len(txtErrCount) > 0 {
		fmt.Println("\n-- text parse errors (by leading token) --")
		keys := sortedKeys(txtErrCount)
		for _, k := range keys {
			fmt.Printf("  %4d  %s\n", txtErrCount[k], k)
		}
		fmt.Println("-- sample failing lines --")
		for _, s := range txtErrs {
			fmt.Printf("  %q\n", s)
		}
	}
	if len(binErrs) > 0 {
		fmt.Println("-- sample binary errors --")
		for _, s := range binErrs {
			fmt.Printf("  %s\n", s)
		}
	}
	if len(unknownSamples) > 0 {
		fmt.Println("-- not-PNB payload samples --")
		for _, s := range unknownSamples {
			fmt.Printf("  %q\n", s)
		}
	}
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- minimal classic-pcap reader (supports named pipes too) ---

type pkt struct {
	dport   int
	payload []byte
}

func readPcap(path string) ([]pkt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)

	hdr := make([]byte, 24)
	if _, err := r.Read(hdr); err != nil {
		return nil, err
	}
	le := false
	switch {
	case hdr[0] == 0xd4 && hdr[1] == 0xc3: // 0xa1b2c3d4 read little-endian
		le = true
	case hdr[0] == 0xa1 && hdr[1] == 0xb2: // big-endian file
		le = false
	case hdr[0] == 0x4d && hdr[1] == 0x3c: // ns pcap little-endian
		le = true
	case hdr[0] == 0xa1 && hdr[1] == 0xb2 && hdr[2] == 0x3c && hdr[3] == 0x4d:
		le = false
	default:
		return nil, fmt.Errorf("not a pcap (magic %x %x %x %x)", hdr[0], hdr[1], hdr[2], hdr[3])
	}
	u32 := func(b []byte) uint32 {
		if le {
			return binary.LittleEndian.Uint32(b)
		}
		return binary.BigEndian.Uint32(b)
	}
	linktype := int(u32(hdr[20:24]))
	fmt.Printf("pcap linktype=%d\n", linktype)

	var out []pkt
	for {
		rec := make([]byte, 16)
		if _, err := r.Read(rec); err != nil {
			break
		}
		incl := u32(rec[8:12])
		if incl == 0 || incl > 65535 {
			break
		}
		data := make([]byte, incl)
		if _, err := r.Read(data); err != nil {
			break
		}
		if pl, dp := extractUDP(data, linktype); pl != nil {
			out = append(out, pkt{dport: dp, payload: pl})
		}
	}
	return out, nil
}

func extractUDP(frame []byte, linktype int) ([]byte, int) {
	off := 0
	switch linktype {
	case 1: // Ethernet
		if len(frame) < 14 {
			return nil, 0
		}
		switch {
		case frame[12] == 0x08 && frame[13] == 0x00: // IPv4
			off = 14
		case frame[12] == 0x86 && frame[13] == 0xdd: // IPv6
			return extractUDPv6(frame, 14)
		default:
			return nil, 0
		}
	case 101, 12: // raw IPv4
		off = 0
	case 113: // Linux cooked SLL (16B)
		if len(frame) < 16 {
			return nil, 0
		}
		et := int(frame[14])<<8 | int(frame[15])
		if et == 0x86dd {
			return extractUDPv6(frame, 16)
		}
		if et != 0x0800 {
			return nil, 0
		}
		off = 16
	case 276: // Linux cooked v2 (SLL2, 20B); ethertype at bytes 0-1
		if len(frame) < 20 {
			return nil, 0
		}
		et := int(frame[0])<<8 | int(frame[1])
		if et == 0x86dd {
			return extractUDPv6(frame, 20)
		}
		if et != 0x0800 {
			return nil, 0
		}
		off = 20
	default:
		return nil, 0
	}
	if off+20 > len(frame) || frame[off]>>4 != 4 {
		return nil, 0
	}
	if frame[off+9] != 17 {
		return nil, 0 // not UDP
	}
	ihl := int(frame[off]&0x0f) * 4
	u := off + ihl
	if u+8 > len(frame) {
		return nil, 0
	}
	dport := int(frame[u+2])<<8 | int(frame[u+3])
	return frame[u+8:], dport
}

// extractUDPv6 assumes off points at the IPv6 header and hunts UDP through
// extension headers.
func extractUDPv6(frame []byte, off int) ([]byte, int) {
	if off+40 > len(frame) {
		return nil, 0
	}
	nh := frame[off+6]
	for hops := 0; hops < 8; hops++ {
		switch nh {
		case 17: // UDP
			u := off + 40
			if u+8 > len(frame) {
				return nil, 0
			}
			dport := int(frame[u+2])<<8 | int(frame[u+3])
			return frame[u+8:], dport
		case 0, 43, 60, 135: // hop-by-hop, routing, dest opts, mobility
			hlen := (int(frame[off+41]) + 1) * 8
			off += hlen
			if off+40 > len(frame) {
				return nil, 0
			}
			nh = frame[off+6]
		default:
			return nil, 0
		}
	}
	return nil, 0
}