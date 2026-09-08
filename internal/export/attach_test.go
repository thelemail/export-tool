package export

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"testing"

	"github.com/thelemail/export-tool/internal/attframe"
)

func pdfPart(payload string) attachedPart {
	return attachedPart{
		header: attframe.Header{
			Version:       1,
			Filename:      "invoice.pdf",
			ContentType:   "application/pdf",
			Disposition:   attframe.DispositionAttachment,
			PlaintextSize: int64(len(payload)),
		},
		payload: []byte(payload),
	}
}

type parsedPart struct {
	contentType string
	disposition string
	filename    string
	contentID   string
	body        []byte
}

func flatten(t *testing.T, raw string) []parsedPart {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out []parsedPart
	collect(t, msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), msg.Header.Get("Content-Disposition"), msg.Header.Get("Content-ID"), body, &out)
	return out
}

func collect(t *testing.T, contentType, encoding, disposition, contentID string, body []byte, out *[]parsedPart) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		r := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
		for {
			p, perr := r.NextRawPart()
			if perr != nil {
				return
			}
			sub, rerr := io.ReadAll(p)
			if rerr != nil {
				t.Fatalf("read part: %v", rerr)
			}
			collect(t, p.Header.Get("Content-Type"), p.Header.Get("Content-Transfer-Encoding"), p.Header.Get("Content-Disposition"), p.Header.Get("Content-ID"), sub, out)
		}
	}
	decoded := body
	if strings.EqualFold(strings.TrimSpace(encoding), "base64") {
		raw, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
		if derr != nil {
			t.Fatalf("base64: %v", derr)
		}
		decoded = raw
	}
	filename := ""
	if _, p, perr := mime.ParseMediaType(disposition); perr == nil {
		filename = p["filename"]
	}
	if filename == "" {
		if _, p, perr := mime.ParseMediaType(contentType); perr == nil {
			filename = p["name"]
		}
	}
	dispositionType := ""
	if dt, _, perr := mime.ParseMediaType(disposition); perr == nil {
		dispositionType = dt
	}
	*out = append(*out, parsedPart{
		contentType: mediaType,
		disposition: dispositionType,
		filename:    filename,
		contentID:   contentID,
		body:        decoded,
	})
}

func findPart(parts []parsedPart, filename string) (parsedPart, bool) {
	for _, p := range parts {
		if p.filename == filename {
			return p, true
		}
	}
	return parsedPart{}, false
}

func TestAttachToMIMEWrapsAPlainBody(t *testing.T) {
	src := "From: a@b\r\nSubject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody text\r\n"
	got := attachToMIME("msg-1", src, []attachedPart{pdfPart("PDF-BYTES")}, nil)

	parts := flatten(t, got)
	text, ok := findPart(parts, "")
	if !ok || strings.TrimSpace(string(text.body)) != "body text" {
		t.Fatalf("body part lost: %#v", parts)
	}
	if text.contentType != "text/plain" {
		t.Fatalf("body content type = %q", text.contentType)
	}
	att, ok := findPart(parts, "invoice.pdf")
	if !ok {
		t.Fatalf("attachment missing: %#v", parts)
	}
	if string(att.body) != "PDF-BYTES" {
		t.Fatalf("payload = %q", att.body)
	}
	if att.contentType != "application/pdf" || att.disposition != "attachment" {
		t.Fatalf("part = %#v", att)
	}
	if !strings.Contains(got, "Subject: hi") || !strings.Contains(got, "From: a@b") {
		t.Fatalf("headers lost:\n%s", got)
	}
	if strings.Count(got, "MIME-Version:") != 1 {
		t.Fatalf("duplicate MIME-Version:\n%s", got)
	}
}

func TestAttachToMIMEKeepsExistingMultipart(t *testing.T) {
	src := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n" +
		"--alt\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
		"--alt\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n" +
		"--alt--\r\n"
	got := attachToMIME("msg-2", src, []attachedPart{pdfPart("X")}, nil)

	parts := flatten(t, got)
	types := map[string]bool{}
	for _, p := range parts {
		types[p.contentType] = true
	}
	if !types["text/plain"] || !types["text/html"] {
		t.Fatalf("alternative parts lost: %#v", parts)
	}
	if _, ok := findPart(parts, "invoice.pdf"); !ok {
		t.Fatalf("attachment missing: %#v", parts)
	}
}

func TestAttachToMIMEPreservesContentIDForInlineParts(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:logo@thelemail\">\r\n"
	inline := attachedPart{
		header: attframe.Header{
			Version:       1,
			Filename:      "logo.png",
			ContentType:   "image/png",
			Disposition:   attframe.DispositionInline,
			ContentID:     "<logo@thelemail>",
			PlaintextSize: 3,
		},
		payload: []byte("PNG"),
	}
	got := attachToMIME("msg-3", src, []attachedPart{inline}, nil)

	part, ok := findPart(flatten(t, got), "logo.png")
	if !ok {
		t.Fatalf("inline part missing:\n%s", got)
	}
	if part.contentID != "<logo@thelemail>" {
		t.Fatalf("content-id = %q", part.contentID)
	}
	if part.disposition != "inline" {
		t.Fatalf("disposition = %q", part.disposition)
	}
}

func TestAttachToMIMESkipsAttachmentsAlreadyInTheBody(t *testing.T) {
	src := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n" +
		"--mix\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
		"--mix\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte("PDF-BYTES")) + "\r\n" +
		"--mix--\r\n"

	got := attachToMIME("msg-4", src, []attachedPart{pdfPart("PDF-BYTES")}, nil)
	if got != src {
		t.Fatalf("message was rewritten:\n%s", got)
	}
	count := 0
	for _, p := range flatten(t, got) {
		if p.filename == "invoice.pdf" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("attachment appears %d times", count)
	}
}

func TestAttachToMIMESkipsInlinePartsAlreadyReferencedByContentID(t *testing.T) {
	src := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/related; boundary=\"rel\"\r\n\r\n" +
		"--rel\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:logo@thelemail\">\r\n" +
		"--rel\r\nContent-Type: image/png\r\nContent-ID: <logo@thelemail>\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nUE5H\r\n" +
		"--rel--\r\n"
	inline := attachedPart{
		header: attframe.Header{
			Version:     1,
			Filename:    "embedded.png",
			ContentType: "image/png",
			Disposition: attframe.DispositionInline,
			ContentID:   "logo@thelemail",
		},
		payload: []byte("PNG"),
	}
	if got := attachToMIME("msg-5", src, []attachedPart{inline}, nil); got != src {
		t.Fatalf("message was rewritten:\n%s", got)
	}
}

func TestAttachToMIMEEncodesNonASCIIFilenames(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	part := pdfPart("X")
	part.header.Filename = "смета счёт.pdf"
	got := attachToMIME("msg-6", src, []attachedPart{part}, nil)

	if !strings.Contains(got, "filename*=") {
		t.Fatalf("filename was not RFC 2231 encoded:\n%s", got)
	}
	found, ok := findPart(flatten(t, got), "смета счёт.pdf")
	if !ok {
		t.Fatalf("attachment missing:\n%s", got)
	}
	if string(found.body) != "X" {
		t.Fatalf("payload = %q", found.body)
	}
}

func TestAttachToMIMEIsDeterministic(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	first := attachToMIME("msg-7", src, []attachedPart{pdfPart("X")}, nil)
	second := attachToMIME("msg-7", src, []attachedPart{pdfPart("X")}, nil)
	if first != second {
		t.Fatal("output is not stable across runs")
	}
	other := attachToMIME("msg-8", src, []attachedPart{pdfPart("X")}, nil)
	if strings.Contains(other, boundaryFor("msg-7")) {
		t.Fatal("boundary is not derived from the message id")
	}
}

func TestAttachToMIMEWritesPlaceholderForLostAttachments(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	got := attachToMIME("msg-9", src, nil, []lostPart{{
		filename:    "invoice.pdf",
		contentType: "application/pdf",
		sizeBytes:   2048,
		reason:      "attframe: bad magic",
	}})

	if !strings.Contains(got, "invoice.pdf") || !strings.Contains(got, "attframe: bad magic") {
		t.Fatalf("placeholder missing:\n%s", got)
	}
	if !strings.Contains(got, "export-report.json") {
		t.Fatalf("placeholder does not point at the report:\n%s", got)
	}
	parts := flatten(t, got)
	if len(parts) != 2 {
		t.Fatalf("expected body + placeholder, got %d", len(parts))
	}
}

func TestPlaceholderNamesTheOrdinalWhenTheFilenameIsUnknown(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	got := attachToMIME("msg-12", src, nil, []lostPart{{ordinal: 1, reason: "http 404: NoSuchKey"}})

	if !strings.Contains(got, "attachment 2 of this message") {
		t.Fatalf("placeholder does not identify the attachment:\n%s", got)
	}
	if strings.Contains(got, "unnamed") || strings.Contains(got, "unknown type") {
		t.Fatalf("placeholder invents details it does not have:\n%s", got)
	}
}

func TestAttachToMIMELeavesMessagesWithNothingToAddAlone(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	if got := attachToMIME("msg-10", src, nil, nil); got != src {
		t.Fatalf("message was rewritten:\n%s", got)
	}
}

func TestAttachToMIMEBase64LinesAreWrapped(t *testing.T) {
	src := "From: a@b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
	got := attachToMIME("msg-11", src, []attachedPart{pdfPart(strings.Repeat("A", 4096))}, nil)
	base64Line := regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	wrapped := 0
	for _, line := range strings.Split(normalize(got), "\n") {
		if !base64Line.MatchString(line) {
			continue
		}
		wrapped++
		if len(line) > base64LineLen {
			t.Fatalf("line of %d chars: %q", len(line), line)
		}
	}
	if wrapped < 2 {
		t.Fatalf("payload was not wrapped across lines")
	}
}
