package transfer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/thelemail/trust/proof"
)

func solveLoginProof(ctx context.Context, raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var challenge altcha.Challenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return "", err
	}
	p := challenge.Parameters
	if p.Algorithm != proof.Algorithm || p.KeyLength != 32 || p.Cost < 1 || p.Cost > 1_000_000 {
		return "", errors.New("unsupported sign-in verification challenge")
	}
	remaining := time.Until(time.Unix(p.ExpiresAt, 0))
	if remaining <= 0 {
		return "", errors.New("sign-in verification expired. Try again")
	}
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: challenge, DeriveKey: altcha.DeriveKeyPBKDF2(), StopChan: ctx.Done(), Timeout: min(remaining, 90*time.Second)})
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", err
	}
	if solution == nil {
		return "", errors.New("sign-in verification expired. Try again")
	}
	payload, err := json.Marshal(altcha.Payload{Challenge: challenge, Solution: *solution})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}
