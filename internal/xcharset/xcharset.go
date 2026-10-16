package xcharset

import (
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ToUTF8 returns s as valid UTF-8. If s is already valid UTF-8 (including the
// empty string and plain ASCII) it is returned unchanged. Otherwise s is
// decoded as GB18030 (a superset of GBK), which is what Panabit devices emit.
// If decoding fails outright the original string is returned so no data is
// silently dropped.
func ToUTF8(s string) string {
	if s == "" || utf8.ValidString(s) {
		return s
	}
	r, _, err := transform.String(simplifiedchinese.GB18030.NewDecoder(), s)
	if err != nil || r == "" {
		return s
	}
	return r
}
