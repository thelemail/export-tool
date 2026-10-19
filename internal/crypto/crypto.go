package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const armorHeader = "-----BEGIN PGP "

type Vault struct {
	keyring openpgp.EntityList
}

type UnlockedKey struct {
	Fingerprint  string
	Fingerprints []string
	Err          error
}

func UnlockVault(armoredPrivateKey string, keyPassword []byte) (*Vault, error) {
	vault, results := UnlockVaultKeys([]string{armoredPrivateKey}, keyPassword)
	if err := results[0].Err; err != nil {
		return nil, err
	}
	return vault, nil
}

func UnlockVaultKeys(armoredPrivateKeys []string, keyPassword []byte) (*Vault, []UnlockedKey) {
	vault := &Vault{}
	results := make([]UnlockedKey, len(armoredPrivateKeys))
	for i, armored := range armoredPrivateKeys {
		entity, err := readOneKey(armored, openpgp.PrivateKeyType)
		if err != nil {
			results[i].Err = err
			continue
		}
		results[i].Fingerprint, results[i].Fingerprints = fingerprints(entity)
		if err := decryptEntity(entity, keyPassword); err != nil {
			results[i].Err = err
			continue
		}
		vault.keyring = append(vault.keyring, entity)
	}
	return vault, results
}

func PublicKeyFingerprints(armoredPublicKey string) (string, []string, error) {
	entity, err := readOneKey(armoredPublicKey, openpgp.PublicKeyType)
	if err != nil {
		return "", nil, err
	}
	primary, all := fingerprints(entity)
	return primary, all, nil
}

func readOneKey(armored, blockType string) (*openpgp.Entity, error) {
	if n := strings.Count(armored, armorHeader); n != 1 {
		return nil, fmt.Errorf("read key: want one armored block, found %d", n)
	}
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("read key: want %s, got %s", blockType, block.Type)
	}
	el, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("read key: want one key, found %d", len(el))
	}
	entity := el[0]
	if blockType == openpgp.PrivateKeyType && entity.PrivateKey == nil {
		return nil, errors.New("read key: no private key material")
	}
	return entity, nil
}

func decryptEntity(e *openpgp.Entity, keyPassword []byte) error {
	if e.PrivateKey.Encrypted {
		if err := e.PrivateKey.Decrypt(keyPassword); err != nil {
			return fmt.Errorf("unlock primary key: %w", err)
		}
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
			if err := sk.PrivateKey.Decrypt(keyPassword); err != nil {
				return fmt.Errorf("unlock subkey: %w", err)
			}
		}
	}
	return nil
}

func fingerprints(e *openpgp.Entity) (string, []string) {
	primary := hex.EncodeToString(e.PrimaryKey.Fingerprint)
	all := []string{primary}
	for _, sk := range e.Subkeys {
		all = append(all, hex.EncodeToString(sk.PublicKey.Fingerprint))
	}
	return primary, all
}

func (v *Vault) Decrypt(ciphertext []byte) ([]byte, error) {
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), v.keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return io.ReadAll(md.UnverifiedBody)
}

func (v *Vault) DecryptArmored(armored string) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("dearmor: %w", err)
	}
	md, err := openpgp.ReadMessage(block.Body, v.keyring, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("read armored message: %w", err)
	}
	return io.ReadAll(md.UnverifiedBody)
}
