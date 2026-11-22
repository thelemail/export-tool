package transfer

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/thelemail/export-tool/internal/api"
)

func TestHTTPStatusReadsThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("import: %w", classify(&api.HTTPError{Status: http.StatusTooManyRequests}))
	if got := HTTPStatus(wrapped); got != http.StatusTooManyRequests {
		t.Fatalf("HTTPStatus = %d", got)
	}
	if got := HTTPStatus(errors.New("offline")); got != 0 {
		t.Fatalf("HTTPStatus(plain) = %d", got)
	}
}
