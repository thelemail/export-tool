package export

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/crypto"
)

const keysDir = "private-keys"

var fingerprintPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

type AccountKey struct {
	Version             int
	Fingerprint         string
	Algorithm           string
	Current             bool
	ActivatedAt         *time.Time
	RetiredAt           *time.Time
	EncryptedPrivateKey string
	Fingerprints        []string
	UnlockError         string
}

func (k AccountKey) file() string {
	return fmt.Sprintf("%s/%d-%s.asc", keysDir, k.Version, k.Fingerprint)
}

func UnlockAccountKeys(resp api.AccountKeysResponse, passphrase []byte) (*crypto.Vault, []AccountKey, error) {
	keys, err := checkKeyList(resp)
	if err != nil {
		return nil, nil, err
	}
	armored := make([]string, len(keys))
	for i, k := range keys {
		armored[i] = k.EncryptedPrivateKey
	}
	vault, results := crypto.UnlockVaultKeys(armored, passphrase)
	for i := range keys {
		k := &keys[i]
		res := results[i]
		if res.Fingerprint != "" && res.Fingerprint != k.Fingerprint {
			return nil, nil, fmt.Errorf("key version %d is listed as %s but the key is %s", k.Version, k.Fingerprint, res.Fingerprint)
		}
		k.Fingerprints = res.Fingerprints
		if len(k.Fingerprints) == 0 {
			k.Fingerprints = publicFingerprints(resp.Keys[i], k.Fingerprint)
		}
		if res.Err == nil {
			continue
		}
		if k.Current {
			return nil, nil, fmt.Errorf("unlock current key %s: %w", k.Fingerprint, res.Err)
		}
		k.UnlockError = res.Err.Error()
	}
	return vault, keys, nil
}

func checkKeyList(resp api.AccountKeysResponse) ([]AccountKey, error) {
	if len(resp.Keys) == 0 {
		return nil, errors.New("key list: the server returned no keys")
	}
	if resp.CurrentVersion < 1 {
		return nil, fmt.Errorf("key list: invalid current version %d", resp.CurrentVersion)
	}
	seen := map[int]bool{}
	seenFp := map[string]bool{}
	current := 0
	keys := make([]AccountKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		fp := strings.ToLower(k.KeyFingerprint)
		switch {
		case k.KeyVersion < 1 || k.KeyVersion > resp.CurrentVersion:
			return nil, fmt.Errorf("key list: invalid key version %d", k.KeyVersion)
		case seen[k.KeyVersion]:
			return nil, fmt.Errorf("key list: key version %d is listed twice", k.KeyVersion)
		case !fingerprintPattern.MatchString(fp):
			return nil, fmt.Errorf("key list: key version %d has an invalid fingerprint", k.KeyVersion)
		case seenFp[fp]:
			return nil, fmt.Errorf("key list: fingerprint %s is listed twice", fp)
		case k.IsCurrent != (k.KeyVersion == resp.CurrentVersion):
			return nil, fmt.Errorf("key list: key version %d disagrees with current version %d", k.KeyVersion, resp.CurrentVersion)
		}
		seen[k.KeyVersion] = true
		seenFp[fp] = true
		if k.IsCurrent {
			current++
		}
		keys = append(keys, AccountKey{
			Version:             k.KeyVersion,
			Fingerprint:         fp,
			Algorithm:           k.KeyAlgorithm,
			Current:             k.IsCurrent,
			ActivatedAt:         k.ActivatedAt,
			RetiredAt:           k.RetiredAt,
			EncryptedPrivateKey: k.EncryptedPrivateKey,
		})
	}
	if current != 1 {
		return nil, fmt.Errorf("key list: current version %d is missing", resp.CurrentVersion)
	}
	return keys, nil
}

func publicFingerprints(k api.AccountKey, primary string) []string {
	if k.PublicKeyArmored != "" {
		if fp, all, err := crypto.PublicKeyFingerprints(k.PublicKeyArmored); err == nil && fp == primary {
			return all
		}
	}
	return []string{primary}
}

func (e *Exporter) keyFor(fingerprint []byte) (AccountKey, bool) {
	fp := hex.EncodeToString(fingerprint)
	for _, k := range e.Keys {
		for _, candidate := range k.Fingerprints {
			if candidate == fp {
				return k, true
			}
		}
	}
	return AccountKey{}, false
}

func (e *Exporter) explainDecrypt(fingerprint []byte, err error) error {
	if len(fingerprint) == 0 {
		return err
	}
	k, ok := e.keyFor(fingerprint)
	if !ok {
		return fmt.Errorf("encrypted to key %s, which is not in this account's key history: %w", hex.EncodeToString(fingerprint), err)
	}
	if k.UnlockError != "" {
		return fmt.Errorf("encrypted to key version %d (%s), which could not be unlocked: %w", k.Version, k.Fingerprint, err)
	}
	return err
}

type keyManifestEntry struct {
	Version     int        `json:"version"`
	Fingerprint string     `json:"fingerprint"`
	Algorithm   string     `json:"algorithm,omitempty"`
	Current     bool       `json:"current"`
	ActivatedAt *time.Time `json:"activatedAt,omitempty"`
	RetiredAt   *time.Time `json:"retiredAt,omitempty"`
	File        string     `json:"file,omitempty"`
	Unlocked    bool       `json:"unlocked"`
	Error       string     `json:"error,omitempty"`
}

type keyManifest struct {
	CurrentVersion int                `json:"currentVersion"`
	Keys           []keyManifestEntry `json:"keys"`
}

func (e *Exporter) keyManifest() keyManifest {
	m := keyManifest{Keys: []keyManifestEntry{}}
	keys := append([]AccountKey(nil), e.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Version > keys[j].Version })
	for _, k := range keys {
		if k.Current {
			m.CurrentVersion = k.Version
		}
		entry := keyManifestEntry{
			Version:     k.Version,
			Fingerprint: k.Fingerprint,
			Algorithm:   k.Algorithm,
			Current:     k.Current,
			ActivatedAt: k.ActivatedAt,
			RetiredAt:   k.RetiredAt,
			Unlocked:    k.UnlockError == "",
			Error:       k.UnlockError,
		}
		if k.EncryptedPrivateKey != "" {
			entry.File = k.file()
		}
		m.Keys = append(m.Keys, entry)
	}
	return m
}

func (e *Exporter) writeKeyMaterial() error {
	if len(e.Keys) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(e.OutDir, keysDir), 0o700); err != nil {
		return err
	}
	for _, k := range e.Keys {
		if k.EncryptedPrivateKey == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(e.OutDir, filepath.FromSlash(k.file())), []byte(k.EncryptedPrivateKey), 0o600); err != nil {
			return err
		}
		if k.Current {
			if err := os.WriteFile(filepath.Join(e.OutDir, "private-key-encrypted.asc"), []byte(k.EncryptedPrivateKey), 0o600); err != nil {
				return err
			}
		}
	}
	raw, err := json.MarshalIndent(e.keyManifest(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.OutDir, "keys.json"), append(raw, '\n'), 0o600)
}

func (e *Exporter) keyWarnings() []keyManifestEntry {
	out := []keyManifestEntry{}
	for _, entry := range e.keyManifest().Keys {
		if entry.Error != "" {
			out = append(out, entry)
		}
	}
	return out
}
