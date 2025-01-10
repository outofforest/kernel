package thttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

const bearerPrefix = "Bearer "

// ErrMissingAuthToken is an error return by BearerToken if there is no Authorization HTTP header.
var ErrMissingAuthToken = errors.New("missing authentication token")

// MalformedAuthHeaderError is an error returned by BearerToken if Authorization HTTP header is not in form
// "Bearer token".
type MalformedAuthHeaderError struct {
	header string
}

func (e MalformedAuthHeaderError) Error() string {
	return fmt.Sprintf("malformed authentication header: %q", e.header)
}

// BearerToken returns a bearer token, or an error if it is not found.
func BearerToken(header http.Header) (string, error) {
	h := header.Get("Authorization")
	if h == "" {
		return "", ErrMissingAuthToken
	}
	if !strings.HasPrefix(h, bearerPrefix) {
		return "", MalformedAuthHeaderError{h}
	}
	return strings.TrimPrefix(h, bearerPrefix), nil
}
