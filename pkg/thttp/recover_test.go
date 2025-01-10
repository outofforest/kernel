package thttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/outofforest/cloudless/pkg/test"
)

func TestRecover(t *testing.T) {
	ctx := test.Context(t)

	handler := Recover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("oops")
	}))

	r := httptest.NewRequest(http.MethodPost, "http://localhost", nil).WithContext(ctx)
	r.Body = io.NopCloser(strings.NewReader("hello"))
	res := TestCtx(ctx, handler, r)
	defer res.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}
