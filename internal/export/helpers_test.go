package export

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/thelemail/export-tool/internal/crypto"
)

type testKey struct {
	entity *openpgp.Entity
	vault  *crypto.Vault
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "export", "test@thelemail.com", nil)
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	vault, err := crypto.UnlockVault(buf.String(), nil)
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	return &testKey{entity: entity, vault: vault}
}

func (k *testKey) encrypt(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{k.entity}, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func (k *testKey) encryptArmored(t *testing.T, plaintext []byte) string {
	t.Helper()
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	w, err := openpgp.Encrypt(aw, []*openpgp.Entity{k.entity}, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	return buf.String()
}

func normalize(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
