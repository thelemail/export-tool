package export

import (
	"strings"

	"github.com/thelemail/export-tool/internal/crypto"
)

const pgpBegin = "-----BEGIN PGP MESSAGE-----"
const pgpEnd = "-----END PGP MESSAGE-----"

// unwrapPgpMime peels an RFC 3156 multipart/encrypted layer when the decrypted
// MIME body is itself an OpenPGP armor (e.g. mail encrypted end-to-end by the
// sender and re-wrapped to the recipient key). Depth-bounded.
func unwrapPgpMime(v *crypto.Vault, mimeStr string) string {
	for depth := 0; depth < 3; depth++ {
		start := strings.Index(mimeStr, pgpBegin)
		if start < 0 {
			return mimeStr
		}
		end := strings.Index(mimeStr, pgpEnd)
		if end < 0 || end < start {
			return mimeStr
		}
		armorBlock := mimeStr[start : end+len(pgpEnd)]
		inner, err := v.DecryptArmored(armorBlock)
		if err != nil {
			return mimeStr
		}
		mimeStr = string(inner)
	}
	return mimeStr
}

func headerValue(mimeStr, name string) string {
	lower := strings.ToLower(name) + ":"
	for _, line := range strings.Split(mimeStr, "\n") {
		if strings.TrimSpace(line) == "" {
			return ""
		}
		if strings.HasPrefix(strings.ToLower(line), lower) {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

func senderAddress(mimeStr string) string {
	from := headerValue(mimeStr, "From")
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j >= 0 {
			return from[i+1 : i+j]
		}
	}
	return strings.TrimSpace(from)
}
