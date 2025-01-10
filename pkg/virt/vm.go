package virt

import (
	_ "embed"
	"os"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
)

//go:embed vm.xml
var vmDef []byte

// CreateVM creates VM.
func CreateVM() ObjectSource {
	return func(_ *host.Configurator) error {
		if err := os.WriteFile("/etc/libvirt/qemu/test.xml", vmDef, 0o600); err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(os.Link("/etc/libvirt/qemu/test.xml",
			"/etc/libvirt/qemu/autostart/test.xml"))
	}
}
