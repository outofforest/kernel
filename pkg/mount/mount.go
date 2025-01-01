package mount

import (
	"os"
	"syscall"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/kernel"
)

// ProcFS mounts procfs.
func ProcFS(dir string) error {
	if err := os.MkdirAll(dir, 0o555); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "proc", 0, ""))
}

// TmpFS mounts tmpfs.
func TmpFS(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "tmpfs", 0, ""))
}

// Root mounts root filesystem.
func Root() error {
	if err := ProcFS("/proc"); err != nil {
		return err
	}
	if err := kernel.LoadModule("overlay"); err != nil {
		return err
	}
	if err := syscall.Unmount("/proc", 0); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Remove("/proc"); err != nil {
		return errors.WithStack(err)
	}

	if err := TmpFS("/overlay"); err != nil {
		return err
	}

	if err := os.MkdirAll("/overlay/upper", 0o755); err != nil {
		return errors.WithStack(err)
	}
	if err := os.MkdirAll("/overlay/work", 0o755); err != nil {
		return errors.WithStack(err)
	}
	if err := os.MkdirAll("/overlay/newroot", 0o755); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Mount("overlay", "/overlay/newroot", "overlay", 0,
		"lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work"); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Chdir("/overlay/newroot"); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Mount("/overlay/newroot", "/", "", syscall.MS_MOVE, ""); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Chroot("."); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Remove("/overlay"); err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(ProcFS("/proc"))
}
