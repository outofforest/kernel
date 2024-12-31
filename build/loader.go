package build

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"

	"github.com/cavaliergopher/cpio"
	"github.com/pkg/errors"

	"github.com/outofforest/build/v2/pkg/tools"
	"github.com/outofforest/build/v2/pkg/types"
	"github.com/outofforest/tools/pkg/tools/golang"
	"github.com/outofforest/tools/pkg/tools/zig"
)

const (
	initBinPath      = "bin/init"
	initramfsPath    = "bin/embed/initramfs"
	kernelPath       = "bin/embed/vmlinuz"
	kernelFilePrefix = "usr/lib/modules/"
	kernelFileSuffix = "/vmlinuz"
)

func buildLoader(ctx context.Context, deps types.DepsFunc) error {
	deps(buildInit, extractKernel, zig.EnsureZig)

	return zig.Build(ctx, deps, zig.BuildConfig{
		PackagePath: "loader",
		OutputPath:  "bin",
	})
}

func extractKernel(ctx context.Context, deps types.DepsFunc) error {
	initramfsF, err := os.Open(initramfsPath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer initramfsF.Close()

	c, err := gzip.NewReader(initramfsF)
	if err != nil {
		return errors.WithStack(err)
	}
	defer c.Close()

	// return nil

	r := cpio.NewReader(c)
	for {
		fInfo, err := r.Next()
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return errors.New("kernel not found in rpm")
		default:
			return errors.WithStack(err)
		}

		if strings.HasPrefix(fInfo.Name, kernelFilePrefix) && strings.HasSuffix(fInfo.Name, kernelFileSuffix) &&
			fInfo.Linkname == "" {
			vmlinuzF, err := os.OpenFile(kernelPath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o700)
			if err != nil {
				return errors.WithStack(err)
			}
			defer vmlinuzF.Close()

			_, err = io.Copy(vmlinuzF, r)
			return errors.WithStack(err)
		}
	}
}

func buildInit(ctx context.Context, deps types.DepsFunc) error {
	deps(golang.EnsureGo)

	return golang.Build(ctx, deps, golang.BuildConfig{
		Platform:      tools.PlatformLocal,
		PackagePath:   "init",
		BinOutputPath: initBinPath,
	})
}
