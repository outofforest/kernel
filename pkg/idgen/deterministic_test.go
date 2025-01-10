package idgen

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeterministic(t *testing.T) {
	foo1 := NewDeterministic("foo")
	foo2 := NewDeterministic("foo")
	bar1 := NewDeterministic("bar")
	bar2 := NewDeterministic("bar")
	for range 10 {
		foo1id := foo1.ID()
		foo2id := foo2.ID()
		bar1id := bar1.ID()
		bar2id := bar2.ID()
		require.Equal(t, foo1id, foo2id)
		require.Equal(t, bar1id, bar2id)
		require.NotEqual(t, foo1id, bar1id)
	}
}
