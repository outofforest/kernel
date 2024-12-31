package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/mount"
	"github.com/outofforest/cloudless/pkg/system"
	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "init", func(ctx context.Context) (retErr error) {
		defer func() {
			if retErr != nil {
				logger.Get(ctx).Error("Error", zap.Error(retErr))
				time.Sleep(30 * time.Second)
			}
		}()

		fmt.Println("I am outofforest init process!")

		if err := mount.ProcFS("/proc"); err != nil {
			return err
		}

		if err := mount.Root(); err != nil {
			return err
		}

		return system.StartSystemD()
	})
}
