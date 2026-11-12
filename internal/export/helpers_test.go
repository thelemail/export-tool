package export

import (
	"strings"
	"testing"
	"time"

	"github.com/thelemail/trust/opaque"
	"github.com/thelemail/trust/pgp"
	"github.com/thelemail/trust/vault"
)

const testAccountID = "6f1c2a7e-3b9d-4c58-a1e0-9d2f4b7c8e15"

type testKey struct {
	key   *pgp.Key
	vault *Vault
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	key, err := pgp.Generate("Test", "test@thelemail.test", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	private, err := key.ArmorPrivate()
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	store := vault.NewStore(opaque.NewStore())
	if err := store.OpenKeys(testAccountID, vault.KeySet{Encrypted: private, KeyVersion: 1}, nil, nil); err != nil {
		t.Fatalf("open vault: %v", err)
	}
	t.Cleanup(store.LockAll)
	return &testKey{key: publicOnly(t, key), vault: NewVault(store, testAccountID)}
}

func publicOnly(t *testing.T, k *pgp.Key) *pgp.Key {
	t.Helper()
	armored, err := k.ArmorPublic()
	if err != nil {
		t.Fatalf("armor public: %v", err)
	}
	public, err := pgp.ParseKey(armored)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	return public
}

func encryptTo(t *testing.T, k *pgp.Key, plaintext []byte) []byte {
	t.Helper()
	out, err := pgp.Encrypt(plaintext, []*pgp.Key{k}, nil, false)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out
}

func (k *testKey) encrypt(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	return encryptTo(t, k.key, plaintext)
}

func (k *testKey) encryptArmored(t *testing.T, plaintext []byte) string {
	t.Helper()
	armored, err := pgp.ArmorMessage(k.encrypt(t, plaintext))
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	return armored
}

func normalize(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
