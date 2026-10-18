package export

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/crypto"
)

const vaultPassphrase = "vault-passphrase"

var (
	v4KeyConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519}
	v6KeyConfig = &packet.Config{V6Keys: true, Algorithm: packet.PubKeyAlgoEd25519}
)

type accountKeyFixture struct {
	entity  *openpgp.Entity
	private string
	public  string
}

func (k accountKeyFixture) fingerprint() string {
	return hex.EncodeToString(k.entity.PrimaryKey.Fingerprint)
}

func (k accountKeyFixture) encrypt(t *testing.T, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{k.entity}, nil, nil, nil)
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

func newAccountKey(t *testing.T, cfg *packet.Config, passphrase string) accountKeyFixture {
	t.Helper()
	entity, err := openpgp.NewEntity("Me", "", "me@thelemail.com", cfg)
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	var pub bytes.Buffer
	pw, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := entity.Serialize(pw); err != nil {
		t.Fatalf("serialize public: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	if err := entity.EncryptPrivateKeys([]byte(passphrase), cfg); err != nil {
		t.Fatalf("lock key: %v", err)
	}
	var priv bytes.Buffer
	w, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatalf("serialize private: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close armor: %v", err)
	}
	if _, err := crypto.UnlockVault(priv.String(), []byte(passphrase)); err != nil {
		t.Fatalf("fixture does not unlock: %v", err)
	}
	reread, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pub.String()))
	if err != nil {
		t.Fatalf("reread public: %v", err)
	}
	return accountKeyFixture{entity: reread[0], private: priv.String(), public: pub.String()}
}

func listed(version int, current bool, k accountKeyFixture) api.AccountKey {
	activated := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(version) * 24 * time.Hour)
	key := api.AccountKey{
		KeyVersion:          version,
		KeyFingerprint:      k.fingerprint(),
		KeyAlgorithm:        "openpgp-curve25519-v6",
		PublicKeyArmored:    k.public,
		EncryptedPrivateKey: k.private,
		IsCurrent:           current,
		ActivatedAt:         &activated,
	}
	if k.entity.PrimaryKey.Version == 4 {
		key.KeyAlgorithm = "openpgp-ed25519"
	}
	if !current {
		retired := activated.Add(24 * time.Hour)
		key.RetiredAt = &retired
	}
	return key
}

type keyHistory struct {
	v4, v6, current accountKeyFixture
	resp            api.AccountKeysResponse
}

func newKeyHistory(t *testing.T) keyHistory {
	t.Helper()
	h := keyHistory{
		v4:      newAccountKey(t, v4KeyConfig, vaultPassphrase),
		v6:      newAccountKey(t, v6KeyConfig, vaultPassphrase),
		current: newAccountKey(t, v6KeyConfig, vaultPassphrase),
	}
	h.resp = api.AccountKeysResponse{
		CurrentVersion: 3,
		Keys: []api.AccountKey{
			listed(3, true, h.current),
			listed(1, false, h.v4),
			listed(2, false, h.v6),
		},
	}
	return h
}

func TestUnlockAccountKeysOpensV4AndV6History(t *testing.T) {
	h := newKeyHistory(t)

	vault, keys, err := UnlockAccountKeys(h.resp, []byte(vaultPassphrase))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("keys = %d", len(keys))
	}
	for _, k := range keys {
		if k.UnlockError != "" {
			t.Fatalf("key %d: %s", k.Version, k.UnlockError)
		}
		if len(k.Fingerprints) < 2 || k.Fingerprints[0] != k.Fingerprint {
			t.Fatalf("key %d fingerprints = %v", k.Version, k.Fingerprints)
		}
	}
	for name, k := range map[string]accountKeyFixture{"v4": h.v4, "v6": h.v6, "current": h.current} {
		plain, err := vault.Decrypt(k.encrypt(t, "mail for "+name))
		if err != nil {
			t.Fatalf("decrypt %s: %v", name, err)
		}
		if string(plain) != "mail for "+name {
			t.Fatalf("plain = %q", plain)
		}
	}
}

func TestUnlockAccountKeysFailsWhenTheCurrentKeyDoesNotUnlock(t *testing.T) {
	h := newKeyHistory(t)
	h.current = newAccountKey(t, v6KeyConfig, "someone else")
	h.resp.Keys[0] = listed(3, true, h.current)

	_, _, err := UnlockAccountKeys(h.resp, []byte(vaultPassphrase))
	if err == nil || !strings.Contains(err.Error(), "unlock current key") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnlockAccountKeysReportsHistoryKeysThatDoNotUnlock(t *testing.T) {
	h := newKeyHistory(t)
	stranger := newAccountKey(t, v4KeyConfig, "someone else")
	h.resp.Keys[1] = listed(1, false, stranger)
	h.resp.Keys[2].EncryptedPrivateKey = "not a key"

	vault, keys, err := UnlockAccountKeys(h.resp, []byte(vaultPassphrase))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	byVersion := map[int]AccountKey{}
	for _, k := range keys {
		byVersion[k.Version] = k
	}
	if byVersion[3].UnlockError != "" {
		t.Fatalf("current: %s", byVersion[3].UnlockError)
	}
	if byVersion[1].UnlockError == "" || byVersion[2].UnlockError == "" {
		t.Fatalf("history errors = %q, %q", byVersion[1].UnlockError, byVersion[2].UnlockError)
	}
	if len(byVersion[2].Fingerprints) < 2 {
		t.Fatalf("unreadable key lost its subkey fingerprints: %v", byVersion[2].Fingerprints)
	}
	if _, err := vault.Decrypt(h.current.encrypt(t, "x")); err != nil {
		t.Fatalf("current key no longer decrypts: %v", err)
	}
}

func TestUnlockAccountKeysRejectsAnInconsistentList(t *testing.T) {
	h := newKeyHistory(t)
	cases := map[string]struct {
		mutate func(r *api.AccountKeysResponse)
		want   string
	}{
		"empty":                 {func(r *api.AccountKeysResponse) { r.Keys = nil }, "returned no keys"},
		"current version zero":  {func(r *api.AccountKeysResponse) { r.CurrentVersion = 0 }, "invalid current version 0"},
		"key version zero":      {func(r *api.AccountKeysResponse) { r.Keys[1].KeyVersion = 0 }, "invalid key version 0"},
		"no current":            {func(r *api.AccountKeysResponse) { r.Keys[0].IsCurrent = false }, "key version 3 disagrees with current version 3"},
		"two current":           {func(r *api.AccountKeysResponse) { r.Keys[2].IsCurrent = true }, "key version 2 disagrees with current version 3"},
		"current missing":       {func(r *api.AccountKeysResponse) { r.CurrentVersion = 4; r.Keys[0].IsCurrent = false }, "current version 4 is missing"},
		"version above":         {func(r *api.AccountKeysResponse) { r.Keys[1].KeyVersion = 4 }, "invalid key version 4"},
		"duplicate version":     {func(r *api.AccountKeysResponse) { r.Keys[1].KeyVersion = 2 }, "key version 2 is listed twice"},
		"duplicate key":         {func(r *api.AccountKeysResponse) { r.Keys[1].KeyFingerprint = r.Keys[2].KeyFingerprint }, "is listed twice"},
		"path in fingerprint":   {func(r *api.AccountKeysResponse) { r.Keys[1].KeyFingerprint = "../../" + strings.Repeat("a", 34) }, "key version 1 has an invalid fingerprint"},
		"uppercase fingerprint": {func(r *api.AccountKeysResponse) { r.Keys[1].KeyFingerprint = strings.ToUpper(r.Keys[1].KeyFingerprint) }, "key version 1 has an invalid fingerprint"},
		"wrong fingerprint":     {func(r *api.AccountKeysResponse) { r.Keys[1].KeyFingerprint = strings.Repeat("a", 40) }, "key version 1 is listed as " + strings.Repeat("a", 40)},
		"gap":                   {func(r *api.AccountKeysResponse) { r.Keys = append(r.Keys[:2:2], r.Keys[3:]...) }, "key version 2 is missing"},
		"wrong current":         {func(r *api.AccountKeysResponse) { r.Keys[0].KeyFingerprint = strings.Repeat("b", 64) }, "key version 3 is listed as " + strings.Repeat("b", 64)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := api.AccountKeysResponse{CurrentVersion: h.resp.CurrentVersion, Keys: append([]api.AccountKey(nil), h.resp.Keys...)}
			tc.mutate(&resp)
			_, _, err := UnlockAccountKeys(resp, []byte(vaultPassphrase))
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestUnlockAccountKeysReportsAHistoryKeyWithNoPrivateKey(t *testing.T) {
	h := newKeyHistory(t)
	h.resp.Keys[2].EncryptedPrivateKey = ""

	_, keys, err := UnlockAccountKeys(h.resp, []byte(vaultPassphrase))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	var missing AccountKey
	for _, k := range keys {
		if k.Version == 2 {
			missing = k
		}
	}
	if missing.UnlockError == "" {
		t.Fatalf("version 2 = %+v, want an unlock error", missing)
	}
	warnings := (&Exporter{Keys: keys}).keyWarnings()
	if len(warnings) != 1 || warnings[0].Version != 2 || warnings[0].Unlocked || warnings[0].Error == "" || warnings[0].File != "" {
		t.Fatalf("key warnings = %+v", warnings)
	}
}

func historyExporter(t *testing.T, f *fakeAPI, resp api.AccountKeysResponse, dir string) *Exporter {
	t.Helper()
	vault, keys, err := UnlockAccountKeys(resp, []byte(vaultPassphrase))
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	client := api.New(f.srv.URL, "http://localhost")
	client.MaxAttempts = 2
	client.Backoff = time.Millisecond
	client.SetSession("token", "account")
	return &Exporter{Client: client, Vault: vault, OutDir: dir, Session: "sess-1", Keys: keys}
}

func mailBody(subject string) string {
	return "From: Alice <alice@example.com>\r\n" +
		"To: me@thelemail.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: Tue, 04 Mar 2026 10:11:12 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		subject + " body\r\n"
}

func TestRunExportsEveryKeyAndDecryptsBothGenerations(t *testing.T) {
	h := newKeyHistory(t)
	f := newFakeAPI(t)
	f.put("body-v4", h.v4.encrypt(t, mailBody("Before rotation")))
	f.put("body-v6", h.v6.encrypt(t, mailBody("Between rotations")))
	f.put("body-now", h.current.encrypt(t, mailBody("After rotation")))
	f.add("inbox", []fakeMessage{
		{id: "m1", bodyKey: "body-v4", bodyKeyFP: h.v4.entity.PrimaryKey.Fingerprint},
		{id: "m2", bodyKey: "body-v6", bodyKeyFP: h.v6.entity.PrimaryKey.Fingerprint},
		{id: "m3", bodyKey: "body-now", bodyKeyFP: h.current.entity.PrimaryKey.Fingerprint},
	})
	dir := t.TempDir()

	if err := historyExporter(t, f, h.resp, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	for _, subject := range []string{"Before rotation", "Between rotations", "After rotation"} {
		if !strings.Contains(mbox, subject+" body") {
			t.Fatalf("mbox is missing %q", subject)
		}
	}

	if got := readFile(t, filepath.Join(dir, "private-key-encrypted.asc")); got != normalize(h.current.private) {
		t.Fatal("private-key-encrypted.asc is not the current key")
	}
	for version, k := range map[int]accountKeyFixture{1: h.v4, 2: h.v6, 3: h.current} {
		path := filepath.Join(dir, "private-keys", strconv.Itoa(version)+"-"+k.fingerprint()+".asc")
		if got := readFile(t, path); got != normalize(k.private) {
			t.Fatalf("%s does not hold key version %d", path, version)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", path, st.Mode().Perm())
		}
	}

	var manifest keyManifest
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "keys.json"))), &manifest); err != nil {
		t.Fatalf("decode keys.json: %v", err)
	}
	if manifest.CurrentVersion != 3 || len(manifest.Keys) != 3 {
		t.Fatalf("manifest = %+v", manifest)
	}
	for i, want := range []accountKeyFixture{h.current, h.v6, h.v4} {
		entry := manifest.Keys[i]
		if entry.Version != 3-i || entry.Fingerprint != want.fingerprint() || entry.Current != (i == 0) || !entry.Unlocked {
			t.Fatalf("manifest entry %d = %+v", i, entry)
		}
		if entry.File != "private-keys/"+strconv.Itoa(entry.Version)+"-"+want.fingerprint()+".asc" {
			t.Fatalf("manifest file = %q", entry.File)
		}
		if (entry.RetiredAt == nil) != entry.Current {
			t.Fatalf("manifest entry %d retiredAt = %v", i, entry.RetiredAt)
		}
	}
	if len(manifest.Keys[2].Fingerprint) != 40 || len(manifest.Keys[0].Fingerprint) != 64 {
		t.Fatalf("fingerprints = %s, %s", manifest.Keys[2].Fingerprint, manifest.Keys[0].Fingerprint)
	}

	r := readReport(t, dir)
	if !r.Complete || len(r.KeyWarnings) != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestRunReportsMailEncryptedToKeysItCannotUse(t *testing.T) {
	h := newKeyHistory(t)
	locked := newAccountKey(t, v4KeyConfig, "lost passphrase")
	h.resp.Keys[1] = listed(1, false, locked)
	stranger := newAccountKey(t, v6KeyConfig, vaultPassphrase)

	f := newFakeAPI(t)
	f.put("body-locked", locked.encrypt(t, mailBody("Old")))
	f.put("body-stranger", stranger.encrypt(t, mailBody("Elsewhere")))
	f.put("body-now", h.current.encrypt(t, mailBody("Now")))
	f.put("att-stranger", stranger.encrypt(t, "frame"))
	f.add("inbox", []fakeMessage{
		{id: "m1", bodyKey: "body-locked", bodyKeyFP: locked.entity.PrimaryKey.Fingerprint},
		{id: "m2", bodyKey: "body-stranger", bodyKeyFP: stranger.entity.PrimaryKey.Fingerprint},
		{
			id:        "m3",
			bodyKey:   "body-now",
			bodyKeyFP: h.current.entity.PrimaryKey.Fingerprint,
			attachments: []fakeAttachment{{
				id: "a1", key: "att-stranger", keyFP: stranger.entity.PrimaryKey.Fingerprint,
			}},
		},
	})
	dir := t.TempDir()

	err := historyExporter(t, f, h.resp, dir).Run(context.Background())
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v", err)
	}

	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if countEntries(mbox) != 1 || !strings.Contains(mbox, "Now body") {
		t.Fatalf("mbox = %q", mbox)
	}

	r := readReport(t, dir)
	reasons := map[string]string{}
	for _, l := range r.Lost {
		reasons[l.MessageID+"/"+l.Stage] = l.Error
	}
	if !strings.Contains(reasons["m1/body"], "key version 1 ("+locked.fingerprint()+"), which could not be unlocked") {
		t.Fatalf("m1 reason = %q", reasons["m1/body"])
	}
	notInHistory := "encrypted to key " + stranger.fingerprint() + ", which is not in this account's key history"
	if !strings.Contains(reasons["m2/body"], notInHistory) {
		t.Fatalf("m2 reason = %q", reasons["m2/body"])
	}
	if !strings.Contains(reasons["m3/attachment"], notInHistory) {
		t.Fatalf("m3 reason = %q", reasons["m3/attachment"])
	}
	if len(r.KeyWarnings) != 1 || r.KeyWarnings[0].Version != 1 || r.KeyWarnings[0].Unlocked || r.KeyWarnings[0].Error == "" {
		t.Fatalf("key warnings = %+v", r.KeyWarnings)
	}
	if got := readFile(t, filepath.Join(dir, "private-keys", "1-"+locked.fingerprint()+".asc")); got != normalize(locked.private) {
		t.Fatal("a key that did not unlock was not written out")
	}
}
