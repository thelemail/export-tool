package export

import (
	"github.com/thelemail/trust/vault"
)

type Vault struct {
	store     *vault.Store
	accountID string
}

func NewVault(store *vault.Store, accountID string) *Vault {
	return &Vault{store: store, accountID: accountID}
}

func (v *Vault) Decrypt(data []byte) ([]byte, error) {
	out, err := v.store.Decrypt(v.accountID, data, nil)
	if err != nil {
		return nil, err
	}
	return out.Data, nil
}
