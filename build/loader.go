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
	initBinPath       = "bin/init"
	initramfsPath     = "bin/embed/initramfs"
	initramfsBasePath = "bin/embed/initramfs.base"
	kernelPath        = "bin/embed/vmlinuz"
	kernelFilePrefix  = "usr/lib/modules/"
	kernelFileSuffix  = "/vmlinuz"
)

func buildLoader(ctx context.Context, deps types.DepsFunc) error {
	deps(prepareEmbeds, zig.EnsureZig)

	return zig.Build(ctx, deps, zig.BuildConfig{
		PackagePath: "loader",
		OutputPath:  "bin",
	})
}

func prepareEmbeds(ctx context.Context, deps types.DepsFunc) error {
	deps(buildInit)

	initramfsF, err := os.OpenFile(initramfsPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.WithStack(err)
	}
	defer initramfsF.Close()

	initramfsBaseF, err := os.Open(initramfsBasePath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer initramfsF.Close()

	tReader := io.TeeReader(initramfsBaseF, initramfsF)
	cReader, err := gzip.NewReader(tReader)
	if err != nil {
		return errors.WithStack(err)
	}
	defer cReader.Close()

	r := cpio.NewReader(cReader)
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

			if _, err := io.Copy(vmlinuzF, r); err != nil {
				return errors.WithStack(err)
			}

			break
		}
	}

	if _, err := io.ReadAll(tReader); err != nil {
		return errors.WithStack(err)
	}

	cWriter := gzip.NewWriter(initramfsF)
	defer cWriter.Close()

	w := cpio.NewWriter(cWriter)
	defer w.Close()

	initF, err := os.Open(initBinPath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer initF.Close()

	initSize, err := initF.Seek(0, io.SeekEnd)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = initF.Seek(0, io.SeekStart)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := w.WriteHeader(&cpio.Header{
		Name: "init",
		Mode: 0o700,
		Size: initSize,
	}); err != nil {
		return errors.WithStack(err)
	}
	_, err = io.Copy(w, initF)
	return errors.WithStack(err)
}

func buildInit(ctx context.Context, deps types.DepsFunc) error {
	deps(golang.EnsureGo)

	return golang.Build(ctx, deps, golang.BuildConfig{
		Platform:      tools.PlatformLocal,
		PackagePath:   "init",
		BinOutputPath: initBinPath,
	})
}
