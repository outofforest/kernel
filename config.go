package cloudless

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/vishvananda/netlink"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
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
	ip := parseIP4(gateway)
	return func(c *host.Configuration) error {
		c.SetGateway(ip)
		return nil
	}
}

// Network defines network.
func Network(mac string, ips ...string) host.Configurator {
	n := host.NetworkConfig{
		MAC: parseMAC(mac),
		IPs: make([]net.IPNet, 0, len(ips)),
	}
	for _, ip := range ips {
		if strings.Contains(ip, ".") {
			n.IPs = append(n.IPs, parseIPNet4(ip))
		} else {
			n.IPs = append(n.IPs, parseIPNet6(ip))
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
		ips = append(ips, parseIP4(d))
	}

	return func(c *host.Configuration) error {
		c.AddDNSes(ips...)
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

func parseMAC(mac string) net.HardwareAddr {
	return lo.Must(net.ParseMAC(mac))
}

func parseIP4(ip string) net.IP {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		panic(errors.New("invalid IP address"))
	}
	parsedIP = parsedIP.To4()
	if parsedIP == nil {
		panic(errors.New("not an IPNet4 address"))
	}

	return parsedIP
}

func parseIP6(ip string) net.IP {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		panic(errors.New("invalid IP address"))
	}

	return parsedIP
}

func parseIPNet4(ip string) net.IPNet {
	parts := strings.Split(ip, "/")
	if len(parts) != 2 {
		panic(errors.New("invalid IP address"))
	}

	maskBits, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}
	if maskBits < 0 || maskBits > 32 {
		panic(errors.New("invalid IP address"))
	}

	return net.IPNet{
		IP:   parseIP4(parts[0]),
		Mask: net.CIDRMask(maskBits, 32),
	}
}

func parseIPNet6(ip string) net.IPNet {
	parts := strings.Split(ip, "/")
	if len(parts) != 2 {
		panic(errors.New("invalid IP address"))
	}

	maskBits, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}
	if maskBits < 0 || maskBits > 128 {
		panic(errors.New("invalid IP address"))
	}

	return net.IPNet{
		IP:   parseIP6(parts[0]),
		Mask: net.CIDRMask(maskBits, 128),
	}
}
