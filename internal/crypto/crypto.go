package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

type Vault struct {
	keyring openpgp.EntityList
}

func UnlockVault(armoredPrivateKey string, keyPassword []byte) (*Vault, error) {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	for _, e := range el {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt(keyPassword); err != nil {
				return nil, fmt.Errorf("unlock primary key: %w", err)
			}
		}
		for _, sk := range e.Subkeys {
			if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
				if err := sk.PrivateKey.Decrypt(keyPassword); err != nil {
					return nil, fmt.Errorf("unlock subkey: %w", err)
				}
			}
		}
	}
	if len(el) == 0 {
		return nil, fmt.Errorf("no private key found")
	}
	return &Vault{keyring: el}, nil
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
