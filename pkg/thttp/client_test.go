package thttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/outofforest/cloudless/pkg/test"
)

func TestTest(t *testing.T) {
	ctx := test.Context(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("hello"))
		assert.NoError(t, err)
	})

	res := TestCtx(ctx, StandardMiddleware(handler), httptest.NewRequest(http.MethodGet, "/", nil))
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), body)
}
