package export

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/thelemail/export-tool/internal/attframe"
)

const base64LineLen = 76

type attachedPart struct {
	header  attframe.Header
	payload []byte
}

type lostPart struct {
	ordinal     int
	filename    string
	contentType string
	sizeBytes   int64
	reason      string
}

func attachToMIME(messageID, mimeStr string, atts []attachedPart, lost []lostPart) string {
	if len(atts) == 0 && len(lost) == 0 {
		return mimeStr
	}
	names, cids := existingParts(mimeStr)
	pending := make([]attachedPart, 0, len(atts))
	for _, a := range atts {
		if alreadyPresent(a.header, names, cids) {
			continue
		}
		pending = append(pending, a)
	}
	if len(pending) == 0 && len(lost) == 0 {
		return mimeStr
	}

	boundary := boundaryFor(messageID)
	outerHeaders, body := splitEntity(mimeStr)

	var kept, inner []string
	for _, block := range headerBlocks(outerHeaders) {
		name := blockName(block)
		if name == "mime-version" {
			continue
		}
		if contentNames[name] {
			inner = append(inner, block)
			continue
		}
		kept = append(kept, block)
	}
	if len(inner) == 0 {
		inner = append(inner, "Content-Type: text/plain; charset=utf-8")
	}

	var b strings.Builder
	for _, block := range kept {
		b.WriteString(block)
		b.WriteString(crlf)
	}
	b.WriteString("MIME-Version: 1.0" + crlf)
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"" + crlf)
	b.WriteString(crlf)

	b.WriteString("--" + boundary + crlf)
	b.WriteString(strings.Join(inner, crlf))
	b.WriteString(crlf + crlf)
	b.WriteString(strings.TrimRight(body, "\r\n"))
	b.WriteString(crlf)

	for _, a := range pending {
		b.WriteString("--" + boundary + crlf)
		writeAttachmentHeaders(&b, a.header)
		b.WriteString(crlf)
		writeBase64(&b, a.payload)
	}
	for _, l := range lost {
		b.WriteString("--" + boundary + crlf)
		b.WriteString("Content-Type: text/plain; charset=utf-8" + crlf)
		b.WriteString("Content-Disposition: inline" + crlf)
		b.WriteString(crlf)
		b.WriteString(placeholderText(l))
		b.WriteString(crlf)
	}
	b.WriteString("--" + boundary + "--" + crlf)
	return b.String()
}

func writeAttachmentHeaders(b *strings.Builder, h attframe.Header) {
	contentType := h.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if h.Filename != "" {
		if formatted := mime.FormatMediaType(contentType, map[string]string{"name": h.Filename}); formatted != "" {
			contentType = formatted
		}
	}
	b.WriteString("Content-Type: " + contentType + crlf)
	b.WriteString("Content-Transfer-Encoding: base64" + crlf)

	disposition := string(attframe.DispositionAttachment)
	if h.Disposition == attframe.DispositionInline {
		disposition = string(attframe.DispositionInline)
	}
	if h.Filename != "" {
		if formatted := mime.FormatMediaType(disposition, map[string]string{"filename": h.Filename}); formatted != "" {
			disposition = formatted
		}
	}
	b.WriteString("Content-Disposition: " + disposition + crlf)
	if h.ContentID != "" {
		b.WriteString("Content-ID: " + bracketCID(h.ContentID) + crlf)
	}
}

func writeBase64(b *strings.Builder, payload []byte) {
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > base64LineLen {
		b.WriteString(encoded[:base64LineLen])
		b.WriteString(crlf)
		encoded = encoded[base64LineLen:]
	}
	if encoded != "" {
		b.WriteString(encoded)
		b.WriteString(crlf)
	}
}

func placeholderText(l lostPart) string {
	what := fmt.Sprintf("attachment %d of this message", l.ordinal+1)
	if l.filename != "" {
		what = fmt.Sprintf("the attachment %q", l.filename)
		if l.contentType != "" {
			what += fmt.Sprintf(" (%s)", l.contentType)
		}
		if l.sizeBytes > 0 {
			what += fmt.Sprintf(", %d bytes,", l.sizeBytes)
		}
	}
	return fmt.Sprintf(
		"[Thelemail export: %s could not be recovered: %s. See export-report.json.]"+crlf,
		what, l.reason,
	)
}

func boundaryFor(messageID string) string {
	sum := sha256.Sum256([]byte(messageID))
	return "=_thelemail_" + hex.EncodeToString(sum[:12])
}

func bracketCID(cid string) string {
	cid = strings.TrimSpace(cid)
	if strings.HasPrefix(cid, "<") && strings.HasSuffix(cid, ">") {
		return cid
	}
	return "<" + cid + ">"
}

func normalizeCID(cid string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(cid), "<>"))
}

func alreadyPresent(h attframe.Header, names, cids map[string]bool) bool {
	if h.ContentID != "" && cids[normalizeCID(h.ContentID)] {
		return true
	}
	return h.Filename != "" && names[strings.ToLower(h.Filename)]
}

func existingParts(mimeStr string) (map[string]bool, map[string]bool) {
	names := map[string]bool{}
	cids := map[string]bool{}
	headers, body := splitEntity(mimeStr)
	walkParts(parseHeaders(headers), body, names, cids, 0)
	return names, cids
}

func walkParts(headers textproto.MIMEHeader, body string, names, cids map[string]bool, depth int) {
	if depth > 8 {
		return
	}
	ct := headers.Get("Content-Type")
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := mediaParam(ct, "boundary")
		if boundary == "" {
			return
		}
		r := multipart.NewReader(strings.NewReader(body), boundary)
		for {
			p, err := r.NextRawPart()
			if err != nil {
				return
			}
			sub, err := io.ReadAll(p)
			if err != nil {
				return
			}
			walkParts(p.Header, string(sub), names, cids, depth+1)
		}
	}
	if cid := headers.Get("Content-Id"); cid != "" {
		cids[normalizeCID(cid)] = true
	}
	if name := partFilename(headers); name != "" {
		names[strings.ToLower(name)] = true
	}
}

func partFilename(headers textproto.MIMEHeader) string {
	if cd := headers.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil && params["filename"] != "" {
			return params["filename"]
		}
		if v := mediaParam(cd, "filename"); v != "" {
			return v
		}
	}
	if ct := headers.Get("Content-Type"); ct != "" {
		if _, params, err := mime.ParseMediaType(ct); err == nil && params["name"] != "" {
			return params["name"]
		}
		if v := mediaParam(ct, "name"); v != "" {
			return v
		}
	}
	return ""
}
