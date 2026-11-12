package export

import (
	"context"
	"fmt"

	"github.com/thelemail/trust/productkeys"
	"github.com/thelemail/trust/vault"

	"github.com/thelemail/export-tool/internal/api"
)

type ProductKeysClient interface {
	ProductKeys(ctx context.Context, product string) (api.ProductKeysResponse, error)
	ProductRootDescriptor(ctx context.Context, product string) (api.ProductBundleResponse, error)
	ProductBundle(ctx context.Context, product, bundleID string, revision int64) (api.ProductBundleResponse, error)
}

func VerifyProductKeys(ctx context.Context, client ProductKeysClient, store *vault.Store, accountID string) (bool, error) {
	pk, err := client.ProductKeys(ctx, productkeys.ProductApp)
	if err != nil {
		return false, fmt.Errorf("fetch product keys: %w", err)
	}
	if pk.Head == nil || pk.Head.Version != 2 {
		return false, nil
	}
	if pk.AuthorityKey == nil || pk.IdentityManifest == nil || pk.Delegation == nil {
		return false, fmt.Errorf("account head v2 without its product keys: %w", productkeys.ErrContext)
	}
	manifest, err := productkeys.ParseIdentityManifest(pk.IdentityManifest.Record)
	if err != nil {
		return false, err
	}
	root, err := client.ProductRootDescriptor(ctx, productkeys.ProductApp)
	if err != nil {
		return false, fmt.Errorf("fetch product root: %w", err)
	}
	product := productkeys.ProductInput{
		Product:          productkeys.ProductApp,
		IdentityManifest: productkeys.SignedRecord{Record: pk.IdentityManifest.Record, Signature: pk.IdentityManifest.Signature},
		Delegation: productkeys.DelegationRecord{
			SignedRecord:     productkeys.SignedRecord{Record: pk.Delegation.Record, Signature: pk.Delegation.Signature},
			SigningPublicKey: pk.Delegation.SigningPublicKey,
		},
	}
	for _, page := range pk.DataManifest {
		product.DataManifest = append(product.DataManifest, productkeys.SignedRecord{Record: page.Record, Signature: page.Signature})
	}
	for _, ref := range manifest.Bundles {
		b, err := client.ProductBundle(ctx, productkeys.ProductApp, ref.BundleID, ref.Revision)
		if err != nil {
			return false, fmt.Errorf("fetch product bundle: %w", err)
		}
		product.Bundles = append(product.Bundles, productkeys.StoredBundle{BundleID: b.BundleID, Revision: b.BundleRevision, Bundle: b.Bundle})
	}
	_, err = store.ReadProductKeys(accountID, productkeys.ReadInput{
		AuthorityKey: pk.AuthorityKey.PublicKey,
		Head: productkeys.HeadInput{
			Raw:              pk.Head.Head,
			MAC:              pk.Head.MAC,
			PreviousHeadHash: pk.Head.PreviousHeadHash,
			Signatures: productkeys.HeadSignatures{
				Authority:  pk.Head.AuthoritySignature,
				Legacy:     pk.Head.LegacySignature,
				Transition: pk.Head.TransitionSignature,
			},
		},
		SecretBundles: []productkeys.StoredBundle{{BundleID: root.BundleID, Revision: root.BundleRevision, Bundle: root.Bundle}},
		Products:      []productkeys.ProductInput{product},
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
