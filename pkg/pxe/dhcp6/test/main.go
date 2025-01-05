package main

import (
	"context"

	"github.com/outofforest/cloudless/pkg/pxe/dhcp6"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "dhcp6", dhcp6.Run)
}
