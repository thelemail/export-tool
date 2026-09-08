package attframe

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	magicV1 = "TMA1"
	version = 0x01

	MaxHeaderBytes = 64 * 1024

	prefixLen = 4 + 1 + 4
)

var (
	ErrMagic       = errors.New("attframe: bad magic")
	ErrVersion     = errors.New("attframe: unsupported version")
	ErrHeader      = errors.New("attframe: bad header")
	ErrTruncated   = errors.New("attframe: truncated payload")
	ErrPayloadSize = errors.New("attframe: payload size mismatch")
)

type Disposition string

const (
	DispositionAttachment Disposition = "attachment"
	DispositionInline     Disposition = "inline"
)

type Header struct {
	Version         int         `json:"v"`
	Filename        string      `json:"filename"`
	ContentType     string      `json:"contentType"`
	Disposition     Disposition `json:"disposition"`
	ContentID       string      `json:"contentId,omitempty"`
	PlaintextSize   int64       `json:"plaintextSize"`
	PlaintextSHA256 []byte      `json:"plaintextSha256,omitempty"`
}

func Parse(b []byte) (Header, []byte, error) {
	h, end, err := parsePrefix(b)
	if err != nil {
		return Header{}, nil, err
	}
	payload := b[end:]
	if int64(len(payload)) != h.PlaintextSize {
		return Header{}, nil, fmt.Errorf("%w: header %d vs payload %d", ErrPayloadSize, h.PlaintextSize, len(payload))
	}
	return h, payload, nil
}

func ParseHeader(b []byte) (Header, error) {
	h, _, err := parsePrefix(b)
	return h, err
}

func parsePrefix(b []byte) (Header, int, error) {
	if len(b) < prefixLen {
		return Header{}, 0, ErrTruncated
	}
	if string(b[:4]) != magicV1 {
		return Header{}, 0, ErrMagic
	}
	if b[4] != version {
		return Header{}, 0, fmt.Errorf("%w: %d", ErrVersion, b[4])
	}
	hl := binary.BigEndian.Uint32(b[5:9])
	if hl == 0 || hl > MaxHeaderBytes {
		return Header{}, 0, fmt.Errorf("%w: header length %d", ErrHeader, hl)
	}
	end := prefixLen + int(hl)
	if len(b) < end {
		return Header{}, 0, ErrTruncated
	}
	var h Header
	if err := json.Unmarshal(b[prefixLen:end], &h); err != nil {
		return Header{}, 0, fmt.Errorf("%w: %w", ErrHeader, err)
	}
	if h.Version != version {
		return Header{}, 0, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	return h, end, nil
}
