//go:build nogithub

package kernel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveModuleAlias(t *testing.T) {
	requireT := require.New(t)

	module, err := resolveModuleAlias("fs-overlay")
	requireT.NoError(err)
	requireT.Equal("overlay", module)
}

func TestBuiltInModule(t *testing.T) {
	requireT := require.New(t)

	isBuiltIn, err := isBuiltInModule("ext4")
	requireT.NoError(err)
	requireT.True(isBuiltIn)
}

func TestResolveModulePath(t *testing.T) {
	requireT := require.New(t)

	modulePath, err := resolveModulePath("overlay")
	requireT.NoError(err)
	requireT.Equal("kernel/fs/overlayfs/overlay.ko.xz", modulePath)
}

func TestFindModulesToLoad(t *testing.T) {
	requireT := require.New(t)

	modulesToLoad, err := findModulesToLoad("kernel/drivers/net/virtio_net.ko.xz")
	requireT.NoError(err)
	requireT.Equal([]string{
		"kernel/drivers/net/virtio_net.ko.xz",
		"kernel/drivers/net/net_failover.ko.xz",
		"kernel/net/core/failover.ko.xz",
	}, modulesToLoad)

	modulesToLoad, err = findModulesToLoad("kernel/fs/overlayfs/overlay.ko.xz")
	requireT.NoError(err)
	requireT.Equal([]string{
		"kernel/fs/overlayfs/overlay.ko.xz",
	}, modulesToLoad)
}

func TestIsLoaded(t *testing.T) {
	requireT := require.New(t)

	loaded, err := isLoaded("kernel/fs/overlayfs/overlay.ko.xz")
	requireT.NoError(err)
	requireT.False(loaded)

	loaded, err = isLoaded("rfkill.ko.xz")
	requireT.NoError(err)
	requireT.True(loaded)

	loaded, err = isLoaded("nonexistingmodule.ko.xz")
	requireT.NoError(err)
	requireT.False(loaded)
}
