package build

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavaliergopher/cpio"
	"github.com/pkg/errors"
	"github.com/sassoftware/go-rpmutils"

	"github.com/outofforest/build/v2/pkg/tools"
	"github.com/outofforest/build/v2/pkg/types"
	"github.com/outofforest/tools/pkg/tools/golang"
	"github.com/outofforest/tools/pkg/tools/zig"
)

const (
	initBinPath   = "bin/init"
	initramfsPath = "bin/embed/initramfs"
	kernelPath    = "bin/embed/vmlinuz"
	//nolint:lll
	kernelCoreURL    = "https://kojipkgs.fedoraproject.org//packages/kernel/6.12.7/200.fc41/x86_64/kernel-core-6.12.7-200.fc41.x86_64.rpm"
	kernelFileSuffix = "vmlinuz"
	kernelSHA256     = "5cd46b0ba12275d811470c84a8d0fbfcda364d278d40be8a9d0ade2d9f396752"
)

func buildLoader(ctx context.Context, deps types.DepsFunc) error {
	deps(buildInitramfs, downloadKernel, zig.EnsureZig)

	return zig.Build(ctx, deps, zig.BuildConfig{
		PackagePath: "loader",
		OutputPath:  "bin",
	})
}

func buildInitramfs(ctx context.Context, deps types.DepsFunc) error {
	deps(buildInit)

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

	if err := os.MkdirAll(filepath.Dir(initramfsPath), 0o700); err != nil {
		return errors.WithStack(err)
	}

	initramfsF, err := os.OpenFile(initramfsPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.WithStack(err)
	}
	defer initramfsF.Close()

	cWriter := gzip.NewWriter(initramfsF)
	defer cWriter.Close()

	w := cpio.NewWriter(cWriter)
	defer w.Close()

	if err := w.WriteHeader(&cpio.Header{
		Name: "init",
		Mode: 0o700,
		Size: initSize,
	}); err != nil {
		return errors.WithStack(err)
	}
	if _, err := io.Copy(w, initF); err != nil {
		return errors.WithStack(err)
	}

	// The /proc/self/exe path used by os.Executable is resolved at init time before procfs is mounted.
	// To make it work fake /proc/self/exe has to be provided before starting GO application as init process.
	return errors.WithStack(w.WriteHeader(&cpio.Header{
		Name:     "proc/self/exe",
		Linkname: "init",
	}))
}

func buildInit(ctx context.Context, deps types.DepsFunc) error {
	deps(golang.EnsureGo)

	return golang.Build(ctx, deps, golang.BuildConfig{
		Platform:      tools.PlatformLocal,
		PackagePath:   "init",
		BinOutputPath: initBinPath,
	})
}

func downloadKernel(ctx context.Context, deps types.DepsFunc) error {
	if err := os.MkdirAll(filepath.Dir(kernelPath), 0o700); err != nil {
		return errors.WithStack(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kernelCoreURL, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()

	rpm, err := rpmutils.ReadRpm(resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}
	pReader, err := rpm.PayloadReaderExtended()
	if err != nil {
		return errors.WithStack(err)
	}

	for {
		fInfo, err := pReader.Next()
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return errors.New("kernel not found in rpm")
		default:
			return errors.WithStack(err)
		}

		if strings.HasSuffix(fInfo.Name(), kernelFileSuffix) && !pReader.IsLink() {
			vmlinuzF, err := os.OpenFile(kernelPath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o700)
			if err != nil {
				return errors.WithStack(err)
			}
			defer vmlinuzF.Close()

			hasher := sha256.New()

			if _, err := io.Copy(vmlinuzF, io.TeeReader(pReader, hasher)); err != nil {
				return errors.WithStack(err)
			}

			if hex.EncodeToString(hasher.Sum(nil)) != kernelSHA256 {
				return errors.New("kernel checksum mismatch")
			}

			return nil
		}
	}
}
