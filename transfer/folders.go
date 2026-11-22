package transfer

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	"github.com/thelemail/trust/opaque"
)

func (s *Session) OpenFolderName(sealed []byte) (string, error) {
	data, err := s.mailbox.Decrypt(sealed)
	if err != nil {
		return "", err
	}
	defer clear(data)
	var meta struct {
		Name string `json:"n"`
	}
	if err := json.Unmarshal(data, &meta); err != nil || strings.TrimSpace(meta.Name) == "" {
		return "", errors.New("invalid encrypted folder name")
	}
	return meta.Name, nil
}

func (s *Session) MigrationKey() ([]byte, error) {
	master, ok := s.store.Opaque.MasterKey(s.AccountID)
	if !ok {
		return nil, errors.New("unlock the destination mailbox first")
	}
	defer opaque.Zero(master)
	return hkdf.Key(sha256.New, master, []byte(s.AccountID), "thelemail/migrator/import-identity/v1", sha256.Size)
}
