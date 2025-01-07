package main

import (
	"context"

	"github.com/outofforest/cloudless/pkg/ssh"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "ssh", ssh.NewService(
		"AAAAC3NzaC1lZDI1NTE5AAAAIN2dcB5WtusXYlJqmiKTUq4KNukMOWPj3VTfp1bn+Nn9",
	).TaskFn)
}
