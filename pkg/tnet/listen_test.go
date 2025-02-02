package tnet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/outofforest/cloudless/pkg/test"
)

func TestListenNoPrefix(t *testing.T) {
	l, err := Listen(test.Context(t), "localhost:")
	require.NoError(t, err)
	require.Equal(t, "tcp", l.Addr().Network())
	require.Regexp(t, `^127\.0\.0\.1:\d+$`, l.Addr().String())
	require.NoError(t, l.Close())
}

func TestListenTCP(t *testing.T) {
	l, err := Listen(test.Context(t), "tcp:localhost:")
	require.NoError(t, err)
	require.Equal(t, "tcp", l.Addr().Network())
	require.Regexp(t, `^127\.0\.0\.1:\d+$`, l.Addr().String())
	require.NoError(t, l.Close())
}

func TestListenUnix(t *testing.T) {
	path := t.TempDir() + "/test.sock"
	l, err := Listen(test.Context(t), "unix:"+path)
	require.NoError(t, err)
	require.Equal(t, "unix", l.Addr().Network())
	require.Equal(t, path, l.Addr().String())
	require.NoError(t, l.Close())
}
