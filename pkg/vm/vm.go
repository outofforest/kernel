package vm

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"text/template"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/parse"
)

var (
	//go:embed vm.tmpl.xml
	vmDef string

	vmDefTmpl = lo.Must(template.New("vm").Parse(vmDef))
)

// Config represents vm configuration.
type Config struct {
	Networks []NetworkConfig
}

// NetworkConfig represents vm's network configuration.
type NetworkConfig struct {
	Name string
	MAC  net.HardwareAddr
}

// Configurator defines function setting the vm configuration.
type Configurator func(vm *Config)

// New creates vm.
func New(name string, cores, memory uint64, configurators ...Configurator) host.Configurator {
	return func(c *host.Configuration) error {
		var vm Config

		vmUUID, err := uuid.NewUUID()
		if err != nil {
			return errors.WithStack(err)
		}

		vmlinuz, err := kernelPath()
		if err != nil {
			return err
		}

		for _, configurator := range configurators {
			configurator(&vm)
		}

		c.RequireInitramfs()
		c.RequireVirt()
		c.RequireKernelModules(kernel.Module{
			Name:   "kvm-intel",
			Params: "nested=Y",
		})
		c.AddHugePages(memory)
		c.Prepare(func(_ context.Context) error {
			filePath := fmt.Sprintf("/etc/libvirt/qemu/%s.xml", name)
			f, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return errors.WithStack(err)
			}
			defer f.Close()

			data := struct {
				UUID     uuid.UUID
				Name     string
				Cores    uint64
				VCPUs    uint64
				Memory   uint64
				Kernel   string
				Initrd   string
				Networks []NetworkConfig
			}{
				UUID:     vmUUID,
				Name:     name,
				Cores:    cores,
				VCPUs:    2 * cores,
				Memory:   memory,
				Kernel:   vmlinuz,
				Initrd:   "/boot/initramfs",
				Networks: vm.Networks,
			}

			if err := vmDefTmpl.Execute(f, data); err != nil {
				return errors.WithStack(err)
			}

			return errors.WithStack(os.Link(filePath,
				filepath.Join(filepath.Dir(filePath), "autostart", filepath.Base(filePath))))
		})
		return nil
	}
}

// Network adds network to the config.
func Network(name, mac string) Configurator {
	return func(vm *Config) {
		vm.Networks = append(vm.Networks, NetworkConfig{
			Name: name,
			MAC:  parse.MAC(mac),
		})
	}
}

func kernelPath() (string, error) {
	release, err := kernel.Release()
	if err != nil {
		return "", err
	}
	return filepath.Join("/usr/lib/modules", release, "vmlinuz"), nil
}
