package xcharset

import "testing"

func TestToUTF8_Passthrough(t *testing.T) {
	if got := ToUTF8("hello"); got != "hello" {
		t.Fatalf("want hello, got %q", got)
	}
	if got := ToUTF8("/path/中文"); got != "/path/中文" {
		t.Fatalf("want utf8 preserved, got %q", got)
	}
}

// GBK bytes for "搜狗五笔输入法" (common sample)
var gbkSouGou = []byte{0xCB, 0xD1, 0xB9, 0xB7, 0xCE, 0xE5, 0xB1, 0xCA, 0xCA, 0xE4, 0xC8, 0xEB, 0xB7, 0xA8}

func TestToUTF8_GBK(t *testing.T) {
	got := ToUTF8(string(gbkSouGou))
	want := "搜狗五笔输入法"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}
