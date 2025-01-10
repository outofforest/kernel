package yum

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/thttp"
	"github.com/outofforest/libexec"
	"github.com/outofforest/parallel"
)

// Port is the port where repository is served.
const Port = 80

// PackageProvider provides the list of packages to download.
type PackageProvider func() []string

// NewService returns new yum repo service.
func NewService(repoRoot string, pkgProvider PackageProvider) host.Service {
	return host.Service{
		Name:   "yum",
		OnExit: parallel.Fail,
		ServiceFn: func(ctx context.Context, _ *host.Configurator) error {
			packages := pkgProvider()
			if len(packages) == 0 {
				return nil
			}

			if err := os.MkdirAll(repoRoot, 0o700); err != nil {
				return errors.WithStack(err)
			}
			cmdInstall := exec.Command("dnf", "install", "-y", "--refresh", "createrepo_c")
			cmdDownload := exec.Command("dnf",
				append([]string{"download", "--resolve", "--alldeps"}, packages...)...)
			cmdDownload.Dir = repoRoot
			cmdRepo := exec.Command("/usr/bin/createrepo", ".")
			cmdRepo.Dir = repoRoot

			if err := libexec.Exec(ctx, cmdInstall, cmdDownload, cmdRepo); err != nil {
				return errors.WithStack(err)
			}

			l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: Port})
			if err != nil {
				return errors.WithStack(err)
			}
			defer l.Close()

			server := thttp.NewServer(l, thttp.Config{
				Handler: http.FileServer(http.Dir(repoRoot)),
			})
			return server.Run(ctx)
		},
	}
}
