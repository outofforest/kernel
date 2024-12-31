package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/outofforest/kernel/init/pkg/kernel"
	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

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

		fmt.Println("I am outofforest init process!")

		if err := kernel.LoadModule("kernel/fs/overlayfs/overlay.ko.xz"); err != nil {
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
