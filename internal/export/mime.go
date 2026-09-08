package export

import (
	"bufio"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/thelemail/export-tool/internal/crypto"
)

const (
	pgpBegin = "-----BEGIN PGP MESSAGE-----"
	pgpEnd   = "-----END PGP MESSAGE-----"
	crlf     = "\r\n"
)

var (
	headerSplit  = regexp.MustCompile(`\r?\n\r?\n`)
	foldedHeader = regexp.MustCompile(`\r?\n[ \t]+`)
	contentNames = map[string]bool{
		"content-type":              true,
		"content-transfer-encoding": true,
		"content-disposition":       true,
		"content-id":                true,
		"content-description":       true,
		"content-language":          true,
		"content-location":          true,
		"mime-version":              true,
	}
)

func splitEntity(raw string) (string, string) {
	m := headerSplit.FindStringIndex(raw)
	if m == nil {
		return raw, ""
	}
	return raw[:m[0]], raw[m[1]:]
}

func headerBlocks(headers string) []string {
	var out []string
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(out) > 0 {
			out[len(out)-1] += crlf + line
			continue
		}
		out = append(out, line)
	}
	return out
}

func blockName(block string) string {
	i := strings.Index(block, ":")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(block[:i]))
}

func headerValue(headers, name string) string {
	want := strings.ToLower(name)
	unfolded := foldedHeader.ReplaceAllString(headers, " ")
	for _, line := range strings.Split(unfolded, "\n") {
		line = strings.TrimSuffix(line, "\r")
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) == want {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}

func mediaParam(value, name string) string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name) + `\s*=\s*"?([^";]+)"?`)
	m := re.FindStringSubmatch(value)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func parseHeaders(headers string) textproto.MIMEHeader {
	r := textproto.NewReader(bufio.NewReader(strings.NewReader(headers + crlf + crlf)))
	h, err := r.ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return textproto.MIMEHeader{}
	}
	return h
}

func isPgpEncryptedMime(raw string) bool {
	headers, _ := splitEntity(raw)
	ct := headerValue(headers, "content-type")
	if !strings.HasPrefix(strings.ToLower(ct), "multipart/encrypted") {
		return false
	}
	protocol := strings.ToLower(mediaParam(ct, "protocol"))
	return protocol == "" || protocol == "application/pgp-encrypted"
}

func extractPgpArmor(raw string) string {
	headers, body := splitEntity(raw)
	ct := headerValue(headers, "content-type")
	if !strings.HasPrefix(strings.ToLower(ct), "multipart/encrypted") {
		return ""
	}
	boundary := mediaParam(ct, "boundary")
	if boundary == "" {
		return ""
	}
	for _, seg := range strings.Split(body, "--"+boundary) {
		if strings.HasPrefix(seg, "--") {
			break
		}
		if strings.TrimSpace(seg) == "" {
			continue
		}
		partHeaders, partBody := splitEntity(strings.TrimLeft(seg, "\r\n"))
		if strings.HasPrefix(strings.ToLower(headerValue(partHeaders, "content-type")), "application/pgp-encrypted") {
			continue
		}
		begin := strings.Index(partBody, pgpBegin)
		if begin < 0 {
			continue
		}
		end := strings.Index(partBody[begin:], pgpEnd)
		if end < 0 {
			return ""
		}
		return partBody[begin : begin+end+len(pgpEnd)]
	}
	return ""
}

func unwrapPgpMime(v *crypto.Vault, mimeStr string) string {
	for depth := 0; depth < 3; depth++ {
		if !isPgpEncryptedMime(mimeStr) {
			return mimeStr
		}
		armorBlock := extractPgpArmor(mimeStr)
		if armorBlock == "" {
			return mimeStr
		}
		inner, err := v.DecryptArmored(armorBlock)
		if err != nil {
			return mimeStr
		}
		mimeStr = spliceEntity(mimeStr, string(inner))
	}
	return mimeStr
}

func spliceEntity(outer, inner string) string {
	outerHeaders, _ := splitEntity(outer)
	innerHeaders, innerBody := splitEntity(inner)

	var kept []string
	for _, block := range headerBlocks(outerHeaders) {
		if contentNames[blockName(block)] {
			continue
		}
		kept = append(kept, block)
	}
	kept = append(kept, headerBlocks(innerHeaders)...)
	return strings.Join(kept, crlf) + crlf + crlf + innerBody
}

func messageDate(mimeStr string) (time.Time, bool) {
	headers, _ := splitEntity(mimeStr)
	raw := headerValue(headers, "Date")
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := mail.ParseDate(raw); err == nil {
		return t, true
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func senderAddress(mimeStr string) string {
	headers, _ := splitEntity(mimeStr)
	from := headerValue(headers, "From")
	if from == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(from); err == nil {
		return addr.Address
	}
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j >= 0 {
			return from[i+1 : i+j]
		}
	}
	return strings.TrimSpace(from)
}
