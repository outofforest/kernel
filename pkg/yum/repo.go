package yum

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/thttp"
	"github.com/outofforest/libexec"
	"github.com/outofforest/parallel"
)

const port = 80

// PackageListProvider provides the list of packages required by any host.
type PackageListProvider interface {
	Packages() []string
}

// Service returns new yum repo service.
func Service(repoRoot string) host.Configurator {
	return func(c *host.Configuration) error {
		c.AddFirewallRules(firewall.OpenV4TCPPort(port))
		c.StartServices(host.ServiceConfig{
			Name:   "yum",
			OnExit: parallel.Continue,
			TaskFn: func(ctx context.Context) error {
				packages := c.Packages()
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

				l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
				if err != nil {
					return errors.WithStack(err)
				}
				defer l.Close()

				server := thttp.NewServer(l, thttp.Config{
					Handler: http.FileServer(http.Dir(repoRoot)),
				})
				return server.Run(ctx)
			},
		})
		return nil
	}
}
