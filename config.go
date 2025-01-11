package cloudless

import (
	"bytes"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/parse"
)

// Deployment converts inlined spec into a slice.
func Deployment(configurators ...host.Configurator) []host.Configurator {
	return configurators
}

// Host defines host configuration.
func Host(hostname string, configurators ...host.Configurator) host.Configurator {
	return func(c *host.Configuration) error {
		cfg, mergeFn := host.NewSubconfiguration(c)
		cfg.SetHostname(hostname)

		var notThisHost bool
		for _, configurator := range configurators {
			err := configurator(cfg)
			switch {
			case err == nil:
			case errors.Is(err, host.ErrNotThisHost):
				notThisHost = true
			default:
				return err
			}
		}

		// This is done like this to register all the required packages in the repo and don't skip anything.
		if notThisHost {
			return nil
		}

		mergeFn()

		return host.ErrHostFound
	}
}

// Gateway defines gateway.
func Gateway(gateway string) host.Configurator {
	ip := parse.IP4(gateway)
	return func(c *host.Configuration) error {
		c.SetGateway(ip)
		return nil
	}
}

// Network defines network.
func Network(mac string, ips ...string) host.Configurator {
	n := host.NetworkConfig{
		MAC: parse.MAC(mac),
		IPs: make([]net.IPNet, 0, len(ips)),
	}
	for _, ip := range ips {
		if strings.Contains(ip, ".") {
			n.IPs = append(n.IPs, parse.IPNet4(ip))
		} else {
			n.IPs = append(n.IPs, parse.IPNet6(ip))
		}
	}

	return func(c *host.Configuration) error {
		links, err := netlink.LinkList()
		if err != nil {
			return errors.WithStack(err)
		}

		for _, l := range links {
			if bytes.Equal(n.MAC, l.Attrs().HardwareAddr) {
				c.AddNetworks(n)
				return nil
			}
		}

		return host.ErrNotThisHost
	}
}

// KernelModules defines kernel modules to load.
func KernelModules(modules ...kernel.Module) host.Configurator {
	return func(c *host.Configuration) error {
		c.RequireKernelModules(modules...)
		return nil
	}
}

// ImmediateKernelModules load kernel modules immediately.
func ImmediateKernelModules(modules ...kernel.Module) host.Configurator {
	return func(_ *host.Configuration) error {
		return host.ConfigureKernelModules(modules)
	}
}

// DNS defines DNS servers.
func DNS(dns ...string) host.Configurator {
	ips := make([]net.IP, 0, len(dns))
	for _, d := range dns {
		ips = append(ips, parse.IP4(d))
	}

	return func(c *host.Configuration) error {
		c.AddDNSes(ips...)
		return nil
	}
}

// RepoMirrors defines package repository mirrors.
func RepoMirrors(mirrors ...string) host.Configurator {
	return func(c *host.Configuration) error {
		c.AddRepoMirrors(mirrors...)
		return nil
	}
}

// DefaultKernelModules is the reasonable list of kernel modules providing networking and storage.
var DefaultKernelModules = []kernel.Module{
	// Networking.
	{Name: "virtio_net"},

	// Storage.
	{Name: "virtio_scsi"},
}

// DefaultDNS is the list of default DNS servers.
var DefaultDNS = []string{
	"1.1.1.1",
	"8.8.8.8",
}
