package attframe

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

const goldenFrame = "544d413101000000977b2276223a312c2266696c656e616d65223a22696e766f6963652e706466222c22636f6e74656e7454797065223a226170706c69636174696f6e2f706466222c22646973706f736974696f6e223a226174746163686d656e74222c22636f6e74656e744964223a225c75303033636c6f676f407468656c656d61696c5c7530303365222c22706c61696e7465787453697a65223a31367d68656c6c6f206174746163686d656e74"

func golden(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(goldenFrame)
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return b
}

func TestParseGoldenFrameFromPlatform(t *testing.T) {
	h, payload, err := Parse(golden(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.Version != 1 {
		t.Fatalf("version = %d", h.Version)
	}
	if h.Filename != "invoice.pdf" {
		t.Fatalf("filename = %q", h.Filename)
	}
	if h.ContentType != "application/pdf" {
		t.Fatalf("contentType = %q", h.ContentType)
	}
	if h.Disposition != DispositionAttachment {
		t.Fatalf("disposition = %q", h.Disposition)
	}
	if h.ContentID != "<logo@thelemail>" {
		t.Fatalf("contentId = %q", h.ContentID)
	}
	if h.PlaintextSize != 16 {
		t.Fatalf("plaintextSize = %d", h.PlaintextSize)
	}
	if string(payload) != "hello attachment" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestParseHeaderReadsPrefixOnly(t *testing.T) {
	full := golden(t)
	h, err := ParseHeader(full[:len(full)-16])
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if h.Filename != "invoice.pdf" {
		t.Fatalf("filename = %q", h.Filename)
	}
}

func TestParseRejectsBadMagic(t *testing.T) {
	b := golden(t)
	b[0] = 'X'
	if _, _, err := Parse(b); !errors.Is(err, ErrMagic) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	b := golden(t)
	b[4] = 0x02
	if _, _, err := Parse(b); !errors.Is(err, ErrVersion) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsTruncatedFrame(t *testing.T) {
	b := golden(t)
	if _, _, err := Parse(b[:12]); !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := Parse(b[:4]); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short prefix err = %v", err)
	}
}

func TestParseRejectsOversizedHeaderLength(t *testing.T) {
	b := golden(t)
	binary.BigEndian.PutUint32(b[5:9], MaxHeaderBytes+1)
	if _, _, err := Parse(b); !errors.Is(err, ErrHeader) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsPayloadSizeMismatch(t *testing.T) {
	b := golden(t)
	if _, _, err := Parse(b[:len(b)-1]); !errors.Is(err, ErrPayloadSize) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := Parse(append(bytes.Clone(b), 'x')); !errors.Is(err, ErrPayloadSize) {
		t.Fatalf("long payload err = %v", err)
	}
}

func TestParseRejectsMalformedHeaderJSON(t *testing.T) {
	b := golden(t)
	b[prefixLen] = '?'
	if _, _, err := Parse(b); !errors.Is(err, ErrHeader) {
		t.Fatalf("err = %v", err)
	}
}
