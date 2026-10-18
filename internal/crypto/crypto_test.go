package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var (
	v4Config = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519}
	v6Config = &packet.Config{V6Keys: true, Algorithm: packet.PubKeyAlgoEd25519}
)

func lockedKey(t *testing.T, cfg *packet.Config, passphrase string) (*openpgp.Entity, string) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", "test@thelemail.com", cfg)
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := entity.EncryptPrivateKeys([]byte(passphrase), cfg); err != nil {
		t.Fatalf("lock key: %v", err)
	}
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	return entity, buf.String()
}

func encryptTo(t *testing.T, e *openpgp.Entity, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{e}, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func TestUnlockVaultKeysDecryptsEveryGeneration(t *testing.T) {
	v4, v4Armored := lockedKey(t, v4Config, "pass")
	v6, v6Armored := lockedKey(t, v6Config, "pass")
	oldMail := encryptTo(t, v4, "old mail")
	newMail := encryptTo(t, v6, "new mail")

	vault, results := UnlockVaultKeys([]string{v6Armored, v4Armored}, []byte("pass"))
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("key %d: %v", i, r.Err)
		}
	}
	if got, want := results[0].Fingerprint, hex.EncodeToString(v6.PrimaryKey.Fingerprint); got != want || len(got) != 64 {
		t.Fatalf("v6 fingerprint = %s, want %s", got, want)
	}
	if got, want := results[1].Fingerprint, hex.EncodeToString(v4.PrimaryKey.Fingerprint); got != want || len(got) != 40 {
		t.Fatalf("v4 fingerprint = %s, want %s", got, want)
	}
	if len(results[1].Fingerprints) != 1+len(v4.Subkeys) {
		t.Fatalf("v4 fingerprints = %v", results[1].Fingerprints)
	}
	for mail, want := range map[string][]byte{"old mail": oldMail, "new mail": newMail} {
		plain, err := vault.Decrypt(want)
		if err != nil {
			t.Fatalf("decrypt %q: %v", mail, err)
		}
		if string(plain) != mail {
			t.Fatalf("plain = %q, want %q", plain, mail)
		}
	}
}

func TestUnlockVaultKeysKeepsGoingPastAKeyThatDoesNotUnlock(t *testing.T) {
	current, currentArmored := lockedKey(t, v6Config, "pass")
	old, oldArmored := lockedKey(t, v4Config, "other")

	vault, results := UnlockVaultKeys([]string{currentArmored, oldArmored}, []byte("pass"))
	if results[0].Err != nil {
		t.Fatalf("current: %v", results[0].Err)
	}
	if results[1].Err == nil {
		t.Fatal("a key locked under another passphrase unlocked")
	}
	if results[1].Fingerprint != hex.EncodeToString(old.PrimaryKey.Fingerprint) {
		t.Fatalf("fingerprint of the locked key = %q", results[1].Fingerprint)
	}
	if _, err := vault.Decrypt(encryptTo(t, current, "x")); err != nil {
		t.Fatalf("decrypt with the current key: %v", err)
	}
	if _, err := vault.Decrypt(encryptTo(t, old, "x")); err == nil {
		t.Fatal("decrypted with a key that never unlocked")
	}
}

func TestUnlockVaultKeysRejectsGluedArmor(t *testing.T) {
	_, a := lockedKey(t, v6Config, "pass")
	_, b := lockedKey(t, v6Config, "pass")

	_, results := UnlockVaultKeys([]string{a + "\n" + b}, []byte("pass"))
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "found 2") {
		t.Fatalf("err = %v", results[0].Err)
	}
}

func TestUnlockVaultKeysRejectsAPublicKey(t *testing.T) {
	entity, _ := lockedKey(t, v6Config, "pass")
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, results := UnlockVaultKeys([]string{buf.String()}, []byte("pass"))
	if results[0].Err == nil {
		t.Fatal("a public key was accepted as a private key")
	}
	primary, all, err := PublicKeyFingerprints(buf.String())
	if err != nil {
		t.Fatalf("public fingerprints: %v", err)
	}
	if primary != hex.EncodeToString(entity.PrimaryKey.Fingerprint) || len(all) != 1+len(entity.Subkeys) {
		t.Fatalf("primary = %s, all = %v", primary, all)
	}
}
