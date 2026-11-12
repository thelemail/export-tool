package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type OpaqueKSFParameters struct {
	Name         string `json:"name"`
	TimeCost     uint64 `json:"timeCost"`
	MemoryKib    uint64 `json:"memoryKib"`
	Threads      uint64 `json:"threads"`
	Salt         []byte `json:"salt"`
	OutputLength int    `json:"outputLength"`
}

type OpaqueParametersResponse struct {
	OpaqueParamsVersion int                 `json:"opaqueParamsVersion"`
	OPRF                string              `json:"oprf"`
	AKE                 string              `json:"ake"`
	KDF                 string              `json:"kdf"`
	MAC                 string              `json:"mac"`
	Hash                string              `json:"hash"`
	KSF                 OpaqueKSFParameters `json:"ksf"`
	KeyFingerprint      string              `json:"keyFingerprint"`
}

func (c *Client) OpaqueParameters(ctx context.Context) (OpaqueParametersResponse, error) {
	var out OpaqueParametersResponse
	err := c.do(ctx, http.MethodGet, "/v1/auth/opaque-parameters", nil, &out)
	return out, err
}

type LoginInitRequest struct {
	Email string `json:"email"`
	KE1   []byte `json:"ke1"`
}

type LoginInitResponse struct {
	ChallengeID string `json:"challengeId"`
	AccountID   string `json:"accountId"`
	KE2         []byte `json:"ke2"`
}

func (c *Client) LoginInit(ctx context.Context, email string, ke1 []byte) (LoginInitResponse, error) {
	var out LoginInitResponse
	err := c.do(ctx, http.MethodPost, "/v1/auth/login/init", LoginInitRequest{Email: email, KE1: ke1}, &out)
	return out, err
}

type LoginCompleteRequest struct {
	ChallengeID string `json:"challengeId"`
	KE3         []byte `json:"ke3"`
}

type TwoFactorChallenge struct {
	PendingToken string   `json:"pendingToken"`
	Methods      []string `json:"methods"`
}

type LoginSessionGrant struct {
	AccountID           string              `json:"accountId"`
	AccessToken         string              `json:"accessToken"`
	ExpiresInSeconds    int                 `json:"expiresInSeconds"`
	WrappedMasterKey    []byte              `json:"wrappedMasterKey"`
	MasterKeyID         []byte              `json:"masterKeyId"`
	OpaqueParamsVersion int                 `json:"opaqueParamsVersion"`
	TwoFactor           *TwoFactorChallenge `json:"twoFactor"`
}

func (c *Client) LoginComplete(ctx context.Context, challengeID string, ke3 []byte) (LoginSessionGrant, error) {
	var out LoginSessionGrant
	err := c.do(ctx, http.MethodPost, "/v1/auth/login/complete", LoginCompleteRequest{ChallengeID: challengeID, KE3: ke3}, &out)
	return out, err
}

type TwoFactorVerifyRequest struct {
	PendingToken string `json:"pendingToken"`
	Code         string `json:"code"`
}

func (c *Client) VerifyTOTP(ctx context.Context, pendingToken, code string) (LoginSessionGrant, error) {
	var out LoginSessionGrant
	err := c.do(ctx, http.MethodPost, "/v1/auth/2fa/totp/verify", TwoFactorVerifyRequest{PendingToken: pendingToken, Code: code}, &out)
	return out, err
}

func (c *Client) VerifyBackupCode(ctx context.Context, pendingToken, code string) (LoginSessionGrant, error) {
	var out LoginSessionGrant
	err := c.do(ctx, http.MethodPost, "/v1/auth/2fa/backup-code/verify", TwoFactorVerifyRequest{PendingToken: pendingToken, Code: code}, &out)
	return out, err
}

type AccountKey struct {
	KeyVersion          int        `json:"keyVersion"`
	KeyFingerprint      string     `json:"keyFingerprint"`
	KeyAlgorithm        string     `json:"keyAlgorithm"`
	PublicKeyArmored    string     `json:"publicKeyArmored"`
	EncryptedPrivateKey string     `json:"encryptedPrivateKey"`
	IsCurrent           bool       `json:"isCurrent"`
	ActivatedAt         *time.Time `json:"activatedAt"`
	RetiredAt           *time.Time `json:"retiredAt"`
}

type AccountKeysResponse struct {
	CurrentVersion int          `json:"currentVersion"`
	Keys           []AccountKey `json:"keys"`
}

func (c *Client) ListMyKeys(ctx context.Context) (AccountKeysResponse, error) {
	var out AccountKeysResponse
	err := c.do(ctx, http.MethodGet, "/v1/me/keys", nil, &out)
	return out, err
}

type BlobPointer struct {
	Path           string `json:"path"`
	SizeBytes      int64  `json:"sizeBytes"`
	SHA256         []byte `json:"sha256"`
	KeyFingerprint []byte `json:"keyFingerprint"`
}

type AttachmentDetail struct {
	ID       string      `json:"id"`
	Ordinal  int         `json:"ordinal"`
	Pointer  BlobPointer `json:"pointer"`
	IsInline bool        `json:"isInline"`
}

type MessageSummary struct {
	ID       string   `json:"id"`
	LabelIDs []string `json:"labelIds"`
}

type MessageListResponse struct {
	Items      []MessageSummary `json:"items"`
	NextCursor string           `json:"nextCursor"`
}

func (c *Client) ListMessages(ctx context.Context, query string) (MessageListResponse, error) {
	var out MessageListResponse
	err := c.do(ctx, http.MethodGet, "/v1/messages?"+query, nil, &out)
	return out, err
}

type MessageDetail struct {
	ID          string             `json:"id"`
	Source      string             `json:"source"`
	Encrypted   bool               `json:"encrypted"`
	Body        BlobPointer        `json:"body"`
	Attachments []AttachmentDetail `json:"attachments"`
}

func (c *Client) GetMessage(ctx context.Context, id string) (MessageDetail, error) {
	var out MessageDetail
	err := c.do(ctx, http.MethodGet, "/v1/messages/"+id, nil, &out)
	return out, err
}

type MailCollection struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	ParentID   string `json:"parentId"`
	Position   int64  `json:"position"`
	SealedMeta []byte `json:"sealedMeta"`
	Deleted    bool   `json:"deleted"`
}

type MailCollectionListResponse struct {
	Collections []MailCollection `json:"collections"`
}

func (c *Client) ListMailCollections(ctx context.Context) ([]MailCollection, error) {
	var out MailCollectionListResponse
	err := c.do(ctx, http.MethodGet, "/v1/mail/collections", nil, &out)
	return out.Collections, err
}

func (c *Client) AccountSettings(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.do(ctx, http.MethodGet, "/v1/account/settings", nil, &out)
	return out, err
}

func (c *Client) Addresses(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.do(ctx, http.MethodGet, "/v1/me/addresses", nil, &out)
	return out, err
}

type ExportHeartbeatRequest struct {
	SessionID string `json:"sessionId,omitempty"`
}

type ExportHeartbeatResponse struct {
	SessionID string `json:"sessionId"`
	ExpiresAt string `json:"expiresAt"`
}

func (c *Client) ExportHeartbeat(ctx context.Context, sessionID string) (ExportHeartbeatResponse, error) {
	var out ExportHeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/v1/lifecycle/export/heartbeat", ExportHeartbeatRequest{SessionID: sessionID}, &out)
	return out, err
}

func (c *Client) ExportComplete(ctx context.Context, sessionID string) error {
	return c.do(ctx, http.MethodPost, "/v1/lifecycle/export/complete", map[string]string{"sessionId": sessionID}, nil)
}

type CryptoAccountHead struct {
	Version             int    `json:"version"`
	StateRevision       int64  `json:"stateRevision"`
	Head                []byte `json:"head"`
	PreviousHeadHash    []byte `json:"previousHeadHash"`
	AuthoritySignature  []byte `json:"authoritySignature"`
	LegacySignature     []byte `json:"legacySignature"`
	TransitionSignature []byte `json:"transitionSignature"`
	MAC                 []byte `json:"mac"`
}

type AccountAuthorityKey struct {
	PublicKey []byte `json:"publicKey"`
}

type ProductManifestPage struct {
	Record    []byte `json:"record"`
	Signature []byte `json:"signature"`
}

type ProductDelegation struct {
	Record           []byte `json:"record"`
	Signature        []byte `json:"signature"`
	SigningPublicKey []byte `json:"signingPublicKey"`
}

type ProductKeysResponse struct {
	Product           string                `json:"product"`
	NativeEnforcement bool                  `json:"nativeEnforcement"`
	Head              *CryptoAccountHead    `json:"head"`
	AuthorityKey      *AccountAuthorityKey  `json:"authorityKey"`
	IdentityManifest  *ProductManifestPage  `json:"identityManifest"`
	DataManifest      []ProductManifestPage `json:"dataManifest"`
	Delegation        *ProductDelegation    `json:"delegation"`
}

type ProductBundleResponse struct {
	BundleID       string `json:"bundleId"`
	BundleRevision int64  `json:"bundleRevision"`
	Bundle         []byte `json:"bundle"`
}

func (c *Client) ProductKeys(ctx context.Context, product string) (ProductKeysResponse, error) {
	var out ProductKeysResponse
	err := c.do(ctx, http.MethodGet, "/v1/me/product-keys/"+url.PathEscape(product), nil, &out)
	return out, err
}

func (c *Client) ProductRootDescriptor(ctx context.Context, product string) (ProductBundleResponse, error) {
	var out ProductBundleResponse
	err := c.do(ctx, http.MethodGet, "/v1/me/product-keys/"+url.PathEscape(product)+"/root-descriptor", nil, &out)
	return out, err
}

func (c *Client) ProductBundle(ctx context.Context, product, bundleID string, revision int64) (ProductBundleResponse, error) {
	var out ProductBundleResponse
	path := fmt.Sprintf("/v1/me/product-keys/%s/bundles/%s/revisions/%d", url.PathEscape(product), url.PathEscape(bundleID), revision)
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}
