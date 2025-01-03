package main

import (
	"context"

	"github.com/outofforest/cloudless/pkg/pxe/tftp"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "tftp", tftp.NewRun("/home/wojciech/sources/cloudless/bin/efi.img"))
}
