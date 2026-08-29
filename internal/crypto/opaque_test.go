package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

const (
	testAccountID = "8f2b6a4c-1d3e-4f50-9a71-2c8d5e6f7a90"
	testPassword  = "correct horse battery staple"
)

type testServer struct {
	conf *opaque.Configuration
	srv  *opaque.Server
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	conf := opaque.DefaultConfiguration()
	conf.Context = nil
	conf.KSF = ksf.Argon2id

	srv, err := conf.Server()
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	sk, pk := conf.KeyGen()
	err = srv.SetKeyMaterial(&opaque.ServerKeyMaterial{
		Identity:       []byte(serverIdentity),
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	})
	if err != nil {
		t.Fatalf("SetKeyMaterial: %v", err)
	}
	return &testServer{conf: conf, srv: srv}
}

func (s *testServer) register(t *testing.T, password, credentialID, clientID []byte) (*opaque.ClientRecord, []byte) {
	t.Helper()

	client, err := s.conf.Client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatalf("RegistrationInit: %v", err)
	}
	resp, err := s.srv.RegistrationResponse(req, credentialID, nil)
	if err != nil {
		t.Fatalf("RegistrationResponse: %v", err)
	}
	record, exportKey, err := client.RegistrationFinalize(resp, clientID, []byte(serverIdentity), clientOptions())
	if err != nil {
		t.Fatalf("RegistrationFinalize: %v", err)
	}
	return &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: credentialID,
		ClientIdentity:       clientID,
	}, exportKey
}

func TestLoginRecoversRegistrationExportKey(t *testing.T) {
	srv := newTestServer(t)
	credentialID := []byte("credential-identifier")
	clientID := []byte(clientIdentityPrefix + testAccountID)

	record, registrationExportKey := srv.register(t, []byte(testPassword), credentialID, clientID)

	login, ke1, err := StartLogin(testPassword)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	defer login.Close()

	parsedKE1, err := srv.srv.Deserialize.KE1(ke1)
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}
	ke2, output, err := srv.srv.GenerateKE2(parsedKE1, record)
	if err != nil {
		t.Fatalf("GenerateKE2: %v", err)
	}

	ke3, exportKey, err := login.Finish(testAccountID, ke2.Serialize())
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !bytes.Equal(exportKey, registrationExportKey) {
		t.Fatal("export key does not match the one from registration")
	}

	parsedKE3, err := srv.srv.Deserialize.KE3(ke3)
	if err != nil {
		t.Fatalf("deserialize KE3: %v", err)
	}
	if err := srv.srv.LoginFinish(parsedKE3, output.ClientMAC); err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	srv := newTestServer(t)
	credentialID := []byte("credential-identifier")
	clientID := []byte(clientIdentityPrefix + testAccountID)

	record, _ := srv.register(t, []byte(testPassword), credentialID, clientID)

	login, ke1, err := StartLogin("not the password")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	defer login.Close()

	parsedKE1, err := srv.srv.Deserialize.KE1(ke1)
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}
	ke2, _, err := srv.srv.GenerateKE2(parsedKE1, record)
	if err != nil {
		t.Fatalf("GenerateKE2: %v", err)
	}

	if _, _, err := login.Finish(testAccountID, ke2.Serialize()); !errors.Is(err, ErrAuth) {
		t.Fatalf("Finish: got %v, want ErrAuth", err)
	}
}

func TestLoginRejectsWrongAccountIdentity(t *testing.T) {
	srv := newTestServer(t)
	credentialID := []byte("credential-identifier")
	clientID := []byte(clientIdentityPrefix + testAccountID)

	record, _ := srv.register(t, []byte(testPassword), credentialID, clientID)

	login, ke1, err := StartLogin(testPassword)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	defer login.Close()

	parsedKE1, err := srv.srv.Deserialize.KE1(ke1)
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}
	ke2, _, err := srv.srv.GenerateKE2(parsedKE1, record)
	if err != nil {
		t.Fatalf("GenerateKE2: %v", err)
	}

	other := "00000000-0000-4000-8000-000000000000"
	if _, _, err := login.Finish(other, ke2.Serialize()); !errors.Is(err, ErrAuth) {
		t.Fatalf("Finish: got %v, want ErrAuth", err)
	}
}

func TestLoginRequiresThePinnedKSFProfile(t *testing.T) {
	srv := newTestServer(t)
	credentialID := []byte("credential-identifier")
	clientID := []byte(clientIdentityPrefix + testAccountID)

	client, err := srv.conf.Client()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := client.RegistrationInit([]byte(testPassword))
	if err != nil {
		t.Fatalf("RegistrationInit: %v", err)
	}
	resp, err := srv.srv.RegistrationResponse(req, credentialID, nil)
	if err != nil {
		t.Fatalf("RegistrationResponse: %v", err)
	}
	registrationRecord, _, err := client.RegistrationFinalize(resp, clientID, []byte(serverIdentity))
	if err != nil {
		t.Fatalf("RegistrationFinalize: %v", err)
	}
	record := &opaque.ClientRecord{
		RegistrationRecord:   registrationRecord,
		CredentialIdentifier: credentialID,
		ClientIdentity:       clientID,
	}

	login, ke1, err := StartLogin(testPassword)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	defer login.Close()

	parsedKE1, err := srv.srv.Deserialize.KE1(ke1)
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}
	ke2, _, err := srv.srv.GenerateKE2(parsedKE1, record)
	if err != nil {
		t.Fatalf("GenerateKE2: %v", err)
	}

	if _, _, err := login.Finish(testAccountID, ke2.Serialize()); !errors.Is(err, ErrAuth) {
		t.Fatalf("Finish: got %v, want ErrAuth", err)
	}
}

const (
	vectorExportKey   = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc"
	vectorMasterKey   = "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a"
	vectorWrapped     = "01111e2b3845525f6c798693a0a445ddf6eabc8fecd594f7e5e70da3d949d713de9fb0d1370ed9a5f197c6c980ebea84eb80e90cc5c6352fa664f6f62a"
	vectorMasterKeyID = "ebd64223564b0362ea7b7fa403a10a62"
	vectorPassphrase  = "KITKNHV5QvV+FdgTVzVsjFg6Dam/q8X8Auet9RXpsmI="
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestUnwrapMasterKeyMatchesWebClient(t *testing.T) {
	amk, err := UnwrapMasterKey(mustHex(t, vectorExportKey), mustHex(t, vectorWrapped))
	if err != nil {
		t.Fatalf("UnwrapMasterKey: %v", err)
	}
	if !bytes.Equal(amk, mustHex(t, vectorMasterKey)) {
		t.Fatalf("master key: got %x", amk)
	}
}

func TestUnwrapMasterKeyRejectsTamperedBlob(t *testing.T) {
	wrapped := mustHex(t, vectorWrapped)
	wrapped[len(wrapped)-1] ^= 0xff
	if _, err := UnwrapMasterKey(mustHex(t, vectorExportKey), wrapped); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}

	short := mustHex(t, vectorWrapped)[:wrappedMasterKeyLen-1]
	if _, err := UnwrapMasterKey(mustHex(t, vectorExportKey), short); err == nil {
		t.Fatal("expected a length error")
	}
}

func TestDeriveMasterKeyIDMatchesWebClient(t *testing.T) {
	id, err := DeriveMasterKeyID(mustHex(t, vectorMasterKey))
	if err != nil {
		t.Fatalf("DeriveMasterKeyID: %v", err)
	}
	if !bytes.Equal(id, mustHex(t, vectorMasterKeyID)) {
		t.Fatalf("master key id: got %x", id)
	}
}

func TestDerivePGPPassphraseMatchesWebClient(t *testing.T) {
	got, err := DerivePGPPassphrase(mustHex(t, vectorMasterKey))
	if err != nil {
		t.Fatalf("DerivePGPPassphrase: %v", err)
	}
	if got != vectorPassphrase {
		t.Fatalf("passphrase: got %s", got)
	}
}

func validParameters() Parameters {
	return Parameters{
		Version:         paramsVersion,
		OPRF:            oprfSuite,
		AKE:             akeSuite,
		KDF:             kdfSuite,
		MAC:             macSuite,
		Hash:            hashSuite,
		KSFName:         ksfName,
		TimeCost:        ksfTimeCost,
		MemoryKiB:       ksfMemoryKiB,
		Threads:         ksfThreads,
		Salt:            make([]byte, ksfSaltLength),
		KSFOutputLength: ksfOutputLength,
	}
}

func TestVerifyParameters(t *testing.T) {
	if err := VerifyParameters(validParameters()); err != nil {
		t.Fatalf("valid parameters rejected: %v", err)
	}

	cases := map[string]func(*Parameters){
		"version":      func(p *Parameters) { p.Version = 2 },
		"oprf":         func(p *Parameters) { p.OPRF = "p256-sha256" },
		"hash":         func(p *Parameters) { p.Hash = "sha256" },
		"ksf name":     func(p *Parameters) { p.KSFName = "scrypt" },
		"time cost":    func(p *Parameters) { p.TimeCost = 1 },
		"memory":       func(p *Parameters) { p.MemoryKiB = 1 << 21 },
		"threads":      func(p *Parameters) { p.Threads = 1 },
		"output":       func(p *Parameters) { p.KSFOutputLength = 32 },
		"salt length":  func(p *Parameters) { p.Salt = make([]byte, 8) },
		"salt content": func(p *Parameters) { p.Salt[0] = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validParameters()
			mutate(&p)
			if err := VerifyParameters(p); err == nil {
				t.Fatal("expected a mismatch error")
			}
		})
	}
}
