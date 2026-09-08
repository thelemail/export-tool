package export

import (
	"strings"
	"testing"
	"time"
)

func pgpMimeMessage(headers, armored string) string {
	return headers + "MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"bnd\"\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"Content-Type: application/pgp-encrypted\r\n\r\n" +
		"Version: 1\r\n" +
		"--bnd\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		armored + "\r\n" +
		"--bnd--\r\n"
}

const outerHeaders = "From: Alice <alice@example.com>\r\n" +
	"To: bob@thelemail.com\r\n" +
	"Subject: Contract\r\n" +
	"Date: Tue, 04 Mar 2026 10:11:12 +0000\r\n" +
	"Message-ID: <x@example.com>\r\n"

func TestUnwrapPgpMimeKeepsOuterHeaders(t *testing.T) {
	key := newTestKey(t)
	inner := "Content-Type: text/plain; charset=utf-8\r\n\r\nhello inner\r\n"
	raw := pgpMimeMessage(outerHeaders, key.encryptArmored(t, []byte(inner)))

	got := normalize(unwrapPgpMime(key.vault, raw))

	for _, want := range []string{
		"From: Alice <alice@example.com>",
		"Subject: Contract",
		"Date: Tue, 04 Mar 2026 10:11:12 +0000",
		"Message-ID: <x@example.com>",
		"Content-Type: text/plain; charset=utf-8",
		"hello inner",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "multipart/encrypted") {
		t.Fatalf("outer content-type survived:\n%s", got)
	}
	if senderAddress(got) != "alice@example.com" {
		t.Fatalf("sender = %q", senderAddress(got))
	}
	when, ok := messageDate(got)
	if !ok || when.UTC().Format(time.RFC3339) != "2026-03-04T10:11:12Z" {
		t.Fatalf("date = %v ok=%v", when, ok)
	}
}

func TestUnwrapPgpMimeUnwrapsNestedLayers(t *testing.T) {
	key := newTestKey(t)
	innermost := "Content-Type: text/plain\r\n\r\ndeep\r\n"
	middle := pgpMimeMessage("", key.encryptArmored(t, []byte(innermost)))
	raw := pgpMimeMessage(outerHeaders, key.encryptArmored(t, []byte(middle)))

	got := normalize(unwrapPgpMime(key.vault, raw))
	if !strings.Contains(got, "deep") {
		t.Fatalf("did not unwrap both layers:\n%s", got)
	}
	if !strings.Contains(got, "Subject: Contract") {
		t.Fatalf("lost outer headers:\n%s", got)
	}
}

func TestUnwrapPgpMimeLeavesQuotedArmorAlone(t *testing.T) {
	key := newTestKey(t)
	raw := "From: Alice <alice@example.com>\r\n" +
		"Subject: Look at this key\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"Here is a block I found:\r\n" +
		key.encryptArmored(t, []byte("secret")) + "\r\n"

	if got := unwrapPgpMime(key.vault, raw); got != raw {
		t.Fatalf("message was rewritten:\n%s", got)
	}
}

func TestUnwrapPgpMimeStopsWhenPayloadIsMissing(t *testing.T) {
	key := newTestKey(t)
	raw := outerHeaders +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"bnd\"\r\n\r\n" +
		"--bnd\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--bnd--\r\n"
	if got := unwrapPgpMime(key.vault, raw); got != raw {
		t.Fatalf("message was rewritten:\n%s", got)
	}
}

func TestMessageDateAcceptsCommonForms(t *testing.T) {
	cases := map[string]string{
		"Tue, 04 Mar 2026 10:11:12 +0000":       "2026-03-04T10:11:12Z",
		"Tue, 4 Mar 2026 10:11:12 GMT":          "2026-03-04T10:11:12Z",
		"4 Mar 2026 12:11:12 +0200":             "2026-03-04T10:11:12Z",
		"Tue, 04 Mar 2026 10:11:12 +0000 (UTC)": "2026-03-04T10:11:12Z",
	}
	for raw, want := range cases {
		got, ok := messageDate("Date: " + raw + "\r\n\r\nbody")
		if !ok {
			t.Fatalf("%q not parsed", raw)
		}
		if got.UTC().Format(time.RFC3339) != want {
			t.Fatalf("%q = %s, want %s", raw, got.UTC().Format(time.RFC3339), want)
		}
	}
}

func TestMessageDateIgnoresBodyLines(t *testing.T) {
	if _, ok := messageDate("From: a@b\r\n\r\nDate: Tue, 04 Mar 2026 10:11:12 +0000\r\n"); ok {
		t.Fatal("read a Date out of the body")
	}
}

func TestHeaderValueUnfoldsContinuations(t *testing.T) {
	raw := "Subject: a very\r\n long subject\r\nFrom: a@b\r\n\r\nbody"
	headers, _ := splitEntity(raw)
	if got := headerValue(headers, "subject"); got != "a very long subject" {
		t.Fatalf("subject = %q", got)
	}
}
