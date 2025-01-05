package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/mount"
	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "init", func(ctx context.Context) (retErr error) {
		defer func() {
			if retErr != nil {
				logger.Get(ctx).Error("Error", zap.Error(retErr))
				time.Sleep(120 * time.Second)
			}
		}()

		fmt.Println("I am outofforest init process!")

		if err := mount.Root(); err != nil {
			return err
		}

		if err := kernel.LoadModule("virtio_net"); err != nil {
			return err
		}

		return host.Run(ctx, config)
	})
}
