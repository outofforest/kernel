package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

func loadOverlay() error {
	f, err := os.Open("/usr/lib/modules/6.12.6-200.fc41.x86_64/kernel/fs/overlayfs/overlay.ko.xz")
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	r, err := xz.NewReader(f)
	if err != nil {
		return errors.WithStack(err)
	}

	mod, err := io.ReadAll(r)
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(unix.InitModule(mod, ""))
}

func main() {
	run.New().Run(context.Background(), "init", func(ctx context.Context) (retErr error) {
		defer func() {
			if retErr != nil {
				logger.Get(ctx).Error("Error", zap.Error(retErr))
			}
			for {
				time.Sleep(time.Second)
			}
		}()

		fmt.Println("I am init 3")

		if err := loadOverlay(); err != nil {
			return err
		}

		if err := os.MkdirAll("/overlay", 0o755); err != nil {
			return errors.WithStack(err)
		}
		if err := syscall.Mount("none", "/overlay", "tmpfs", 0, ""); err != nil {
			return errors.WithStack(err)
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

		return errors.WithStack(syscall.Exec("/usr/lib/systemd/systemd", []string{"--system"}, []string{}))
	})
}
