package transfer

import (
	"errors"
	"net/http"
	"time"

	"github.com/thelemail/export-tool/internal/api"
)

var (
	ErrWrongPassword       = errors.New("the email address or password is incorrect")
	ErrRateLimited         = errors.New("too many sign-in attempts")
	ErrProofFailed         = errors.New("the sign-in check could not be completed")
	ErrSuspended           = errors.New("this account is suspended")
	ErrUpgradeRequired     = errors.New("this account has to finish its security upgrade in the browser first")
	ErrVerificationExpired = errors.New("verification expired")
	ErrNoSecondFactor      = errors.New("none of this account's verification methods works in this app")
	ErrSessionEnded        = api.ErrSessionEnded
)

type WaitError struct {
	Err  error
	Wait time.Duration
}

func (e *WaitError) Error() string { return e.Err.Error() }

func (e *WaitError) Unwrap() error { return e.Err }

type problem struct {
	kind  error
	cause error
}

func (p *problem) Error() string { return p.kind.Error() }

func (p *problem) Unwrap() []error { return []error{p.kind, p.cause} }

func because(kind, cause error) error { return &problem{kind: kind, cause: cause} }

func classify(err error) error {
	var he *api.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	switch {
	case he.Status == http.StatusTooManyRequests:
		return &WaitError{Err: because(ErrRateLimited, err), Wait: he.RetryAfter}
	case he.Status == http.StatusUnauthorized:
		return because(ErrWrongPassword, err)
	case he.Code == "account_suspended":
		return because(ErrSuspended, err)
	case he.Code == "proof_required", he.Code == "proof_invalid", he.Code == "proof_expired", he.Code == "proof_reused":
		return because(ErrProofFailed, err)
	}
	return err
}
