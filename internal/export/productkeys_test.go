package export

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/thelemail/trust/opaque"
	"github.com/thelemail/trust/pgp"
	"github.com/thelemail/trust/productkeys/productkeystest"
	"github.com/thelemail/trust/vault"

	"github.com/thelemail/export-tool/internal/api"
)

type productKeysServer struct {
	account productkeystest.Account
	noHead  bool
	noRoot  bool
	badMAC  bool
}

func (s productKeysServer) ProductKeys(_ context.Context, product string) (api.ProductKeysResponse, error) {
	pk := s.account.ProductKeys
	out := api.ProductKeysResponse{
		Product:          product,
		AuthorityKey:     &api.AccountAuthorityKey{PublicKey: pk.AuthorityKey.PublicKey},
		IdentityManifest: &api.ProductManifestPage{Record: pk.IdentityManifest.Record, Signature: pk.IdentityManifest.Signature},
		Delegation:       &api.ProductDelegation{Record: pk.Delegation.Record, Signature: pk.Delegation.Signature, SigningPublicKey: pk.Delegation.SigningPublicKey},
	}
	for _, p := range pk.DataManifest {
		out.DataManifest = append(out.DataManifest, api.ProductManifestPage{Record: p.Record, Signature: p.Signature})
	}
	if !s.noHead {
		h := pk.Head
		out.Head = &api.CryptoAccountHead{
			Version: h.Version, StateRevision: h.StateRevision, Head: h.Head, PreviousHeadHash: h.PreviousHeadHash,
			AuthoritySignature: h.AuthoritySignature, LegacySignature: h.LegacySignature, TransitionSignature: h.TransitionSignature, MAC: h.MAC,
		}
		if s.badMAC {
			out.Head.MAC = make([]byte, len(h.MAC))
		}
	}
	return out, nil
}

func (s productKeysServer) ProductRootDescriptor(context.Context, string) (api.ProductBundleResponse, error) {
	if s.noRoot {
		return api.ProductBundleResponse{}, &api.HTTPError{Status: 403}
	}
	r := s.account.RootDescriptor
	return api.ProductBundleResponse{BundleID: r.BundleID, BundleRevision: r.BundleRevision, Bundle: r.Bundle}, nil
}

func (s productKeysServer) ProductBundle(_ context.Context, _, bundleID string, revision int64) (api.ProductBundleResponse, error) {
	for _, b := range s.account.ProductBundles {
		if b.BundleID == bundleID && b.BundleRevision == revision {
			return api.ProductBundleResponse{BundleID: b.BundleID, BundleRevision: b.BundleRevision, Bundle: b.Bundle}, nil
		}
	}
	return api.ProductBundleResponse{}, &api.HTTPError{Status: 404}
}

func newProductKeysAccount(t *testing.T) (*vault.Store, productkeystest.Account) {
	t.Helper()
	accountID := uuid.MustParse(testAccountID)
	amk := make([]byte, 32)
	if _, err := rand.Read(amk); err != nil {
		t.Fatal(err)
	}
	passphrase, err := opaque.NewStore().AdoptMasterKey(testAccountID, amk)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pgp.Generate("Test", "test@thelemail.test", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	account, err := productkeystest.Build(accountID, amk, []byte(passphrase), key.Entity, rand.Reader, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Lock([]byte(passphrase)); err != nil {
		t.Fatal(err)
	}
	private, err := key.ArmorPrivate()
	if err != nil {
		t.Fatal(err)
	}
	store := vault.NewStore(opaque.NewStore())
	if err := store.OpenWithMasterKey(testAccountID, vault.KeySet{Encrypted: private, KeyVersion: 1}, amk); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.LockAll)
	return store, account
}

func TestVerifyProductKeysReadsAnAccountHeadV2(t *testing.T) {
	store, account := newProductKeysAccount(t)
	v2, err := VerifyProductKeys(context.Background(), productKeysServer{account: account}, store, testAccountID)
	if err != nil || !v2 {
		t.Fatalf("verify: %v %v", v2, err)
	}
}

func TestVerifyProductKeysSkipsAccountsWithoutAHead(t *testing.T) {
	store, account := newProductKeysAccount(t)
	v2, err := VerifyProductKeys(context.Background(), productKeysServer{account: account, noHead: true}, store, testAccountID)
	if err != nil || v2 {
		t.Fatalf("verify without a head: %v %v", v2, err)
	}
}

func TestVerifyProductKeysRefusesWhatItCannotVerify(t *testing.T) {
	store, account := newProductKeysAccount(t)
	if _, err := VerifyProductKeys(context.Background(), productKeysServer{account: account, badMAC: true}, store, testAccountID); err == nil {
		t.Fatal("accepted a forged head mac")
	}
	var httpErr *api.HTTPError
	if _, err := VerifyProductKeys(context.Background(), productKeysServer{account: account, noRoot: true}, store, testAccountID); !errors.As(err, &httpErr) {
		t.Fatalf("missing root gave %v", err)
	}
}
