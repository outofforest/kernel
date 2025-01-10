package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "cloudless", func(ctx context.Context) error {
		fmt.Println("I am cloudless init process.")

		err := host.Run(ctx, cfg)
		if err != nil {
			logger.Get(ctx).Error("Error", zap.Error(err))
			time.Sleep(120 * time.Second)
		}

		return err
	})
}
