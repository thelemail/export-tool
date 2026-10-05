package api

import (
	"context"
	"encoding/json"
	"net/http"
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
	EncryptedPrivateKey string              `json:"encryptedPrivateKey"`
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

type PresignedPointer struct {
	URL            string    `json:"url"`
	ExpiresAt      time.Time `json:"expiresAt"`
	SizeBytes      int64     `json:"sizeBytes"`
	SHA256         []byte    `json:"sha256"`
	KeyFingerprint []byte    `json:"keyFingerprint"`
}

type AttachmentDetail struct {
	ID       string           `json:"id"`
	Ordinal  int              `json:"ordinal"`
	Pointer  PresignedPointer `json:"pointer"`
	IsInline bool             `json:"isInline"`
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
	Body        PresignedPointer   `json:"body"`
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
