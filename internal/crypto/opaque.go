package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

const (
	clientIdentityPrefix = "thelemail/auth/opaque/v1:"
	serverIdentity       = "thelemail.com"

	ksfName         = "argon2id"
	ksfTimeCost     = 3
	ksfMemoryKiB    = 65536
	ksfThreads      = 4
	ksfSaltLength   = 16
	ksfOutputLength = 64

	paramsVersion = 1
	oprfSuite     = "ristretto255-sha512"
	akeSuite      = "ristretto255-sha512"
	kdfSuite      = "sha512"
	macSuite      = "sha512"
	hashSuite     = "sha512"

	infoMasterKeyWrap = "thelemail/amk-wrap/v1"
	infoMasterKeyID   = "thelemail/amk-id/v1"
	infoPGPPassphrase = "thelemail/pgp-passphrase/v1" //nolint:gosec

	wrappedMasterKeyLen = 61
	masterKeyIDLen      = 16
	wrapVersion         = 0x01
	wrapNonceLen        = 12
)

var ErrAuth = errors.New("invalid email or password")

type Login struct {
	client *opaque.Client
	opts   *opaque.ClientOptions
}

func clientOptions() *opaque.ClientOptions {
	return &opaque.ClientOptions{
		KSFSalt:       make([]byte, ksfSaltLength),
		KSFParameters: []uint64{ksfTimeCost, ksfMemoryKiB, ksfThreads},
		KSFLength:     ksfOutputLength,
	}
}

func configuration() *opaque.Configuration {
	conf := opaque.DefaultConfiguration()
	conf.Context = nil
	conf.KSF = ksf.Argon2id
	return conf
}

func StartLogin(password string) (*Login, []byte, error) {
	client, err := configuration().Client()
	if err != nil {
		return nil, nil, fmt.Errorf("opaque client: %w", err)
	}
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("opaque ke1: %w", err)
	}
	return &Login{client: client, opts: clientOptions()}, ke1.Serialize(), nil
}

func (l *Login) Finish(accountID string, ke2 []byte) ([]byte, []byte, error) {
	parsed, err := l.client.Deserialize.KE2(ke2)
	if err != nil {
		return nil, nil, ErrAuth
	}
	ke3, _, exportKey, err := l.client.GenerateKE3(
		parsed,
		[]byte(clientIdentityPrefix+accountID),
		[]byte(serverIdentity),
		l.opts,
	)
	if err != nil {
		return nil, nil, ErrAuth
	}
	return ke3.Serialize(), exportKey, nil
}

func (l *Login) Close() { l.client.ClearState() }

func expand(secret []byte, info string, length int) ([]byte, error) {
	out, err := hkdf.Key(sha256.New, secret, nil, info, length)
	if err != nil {
		return nil, fmt.Errorf("hkdf %s: %w", info, err)
	}
	return out, nil
}

func UnwrapMasterKey(exportKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) != wrappedMasterKeyLen || wrapped[0] != wrapVersion {
		return nil, fmt.Errorf("wrapped master key: unexpected format")
	}
	keyBytes, err := expand(exportKey, infoMasterKeyWrap, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	amk, err := aead.Open(nil, wrapped[1:1+wrapNonceLen], wrapped[1+wrapNonceLen:], []byte(infoMasterKeyWrap))
	if err != nil {
		return nil, ErrAuth
	}
	return amk, nil
}

func DeriveMasterKeyID(amk []byte) ([]byte, error) {
	return expand(amk, infoMasterKeyID, masterKeyIDLen)
}

func DerivePGPPassphrase(amk []byte) (string, error) {
	out, err := expand(amk, infoPGPPassphrase, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

type Parameters struct {
	Version         int
	OPRF            string
	AKE             string
	KDF             string
	MAC             string
	Hash            string
	KSFName         string
	TimeCost        uint64
	MemoryKiB       uint64
	Threads         uint64
	Salt            []byte
	KSFOutputLength int
}

func VerifyParameters(p Parameters) error {
	mismatch := func(field string, want, got any) error {
		return fmt.Errorf("server OPAQUE parameters differ from this build: %s is %v, expected %v", field, got, want)
	}
	switch {
	case p.Version != paramsVersion:
		return mismatch("opaqueParamsVersion", paramsVersion, p.Version)
	case p.OPRF != oprfSuite:
		return mismatch("oprf", oprfSuite, p.OPRF)
	case p.AKE != akeSuite:
		return mismatch("ake", akeSuite, p.AKE)
	case p.KDF != kdfSuite:
		return mismatch("kdf", kdfSuite, p.KDF)
	case p.MAC != macSuite:
		return mismatch("mac", macSuite, p.MAC)
	case p.Hash != hashSuite:
		return mismatch("hash", hashSuite, p.Hash)
	case p.KSFName != ksfName:
		return mismatch("ksf.name", ksfName, p.KSFName)
	case p.TimeCost != ksfTimeCost:
		return mismatch("ksf.timeCost", ksfTimeCost, p.TimeCost)
	case p.MemoryKiB != ksfMemoryKiB:
		return mismatch("ksf.memoryKib", ksfMemoryKiB, p.MemoryKiB)
	case p.Threads != ksfThreads:
		return mismatch("ksf.threads", ksfThreads, p.Threads)
	case p.KSFOutputLength != ksfOutputLength:
		return mismatch("ksf.outputLength", ksfOutputLength, p.KSFOutputLength)
	case len(p.Salt) != ksfSaltLength:
		return mismatch("ksf.salt length", ksfSaltLength, len(p.Salt))
	}
	for _, b := range p.Salt {
		if b != 0 {
			return fmt.Errorf("server OPAQUE parameters differ from this build: ksf.salt is not all zero")
		}
	}
	return nil
}
