package host

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/outofforest/cloudless/pkg/kernel"
)

// Config contains host configuration.
type Config struct {
	Hostname      string
	KernelModules []string
	Networks      []Network
	DNS           []net.IP
}

// Network contains network configuration.
type Network struct {
	MAC     net.HardwareAddr
	IPs     []net.IPNet
	Gateway net.IP
}

// Configure configures host.
func Configure(config []Config) error {
	if err := configureIPv6(); err != nil {
		return err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, l := range links {
		hwAddr := l.Attrs().HardwareAddr
		for _, hc := range config {
			for _, n := range hc.Networks {
				if bytes.Equal(n.MAC, hwAddr) {
					return configureHost(hc)
				}
			}
		}
	}

	return errors.Errorf("no matching link found")
}

func configureHost(hc Config) error {
	if err := configureHostname(hc.Hostname); err != nil {
		return err
	}
	if err := configureKernelModules(hc.KernelModules); err != nil {
		return err
	}
	if err := configureDNS(hc.DNS); err != nil {
		return err
	}
	return configureNetworks(hc.Networks)
}

func configureKernelModules(modules []string) error {
	for _, m := range modules {
		if err := kernel.LoadModule(m); err != nil {
			return err
		}
	}
	return nil
}

func configureHostname(hostname string) error {
	return errors.WithStack(os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0o644))
}

func configureDNS(dns []net.IP) error {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	for _, d := range dns {
		if _, err := fmt.Fprintf(f, "nameserver %s\n", d); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func configureNetworks(networks []Network) error {
	links, err := netlink.LinkList()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, nc := range networks {
		var found bool
		for _, l := range links {
			if bytes.Equal(nc.MAC, l.Attrs().HardwareAddr) {
				if err := configureNetwork(nc, l); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return errors.Errorf("link %s not found", nc.MAC)
		}
	}

	return nil
}

func configureNetwork(nc Network, l netlink.Link) error {
	lName := l.Attrs().Name
	if err := configureIPv6OnInterface(lName); err != nil {
		return err
	}

	var ip6Found bool
	for _, ip := range nc.IPs {
		if ip.IP.To4() == nil {
			ip6Found = true
		}

		if err := netlink.AddrAdd(l, &netlink.Addr{
			IPNet: &ip,
		}); err != nil {
			return errors.WithStack(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return errors.WithStack(err)
		}
	}

	if nc.Gateway != nil {
		if err := netlink.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: l.Attrs().Index,
			Gw:        nc.Gateway,
		}); err != nil {
			return errors.WithStack(err)
		}
	}

	if !ip6Found {
		if err := setSysctl(filepath.Join("net/ipv6/conf", lName, "disable_ipv6"), "1"); err != nil {
			return err
		}
	}

	return nil
}

func configureIPv6OnInterface(lName string) error {
	if err := setSysctl(filepath.Join("net/ipv6/conf", lName, "autoconf"), "0"); err != nil {
		return err
	}
	if err := setSysctl(filepath.Join("net/ipv6/conf", lName, "accept_ra"), "0"); err != nil {
		return err
	}
	return setSysctl(filepath.Join("net/ipv6/conf", lName, "addr_gen_mode"), "1")
}

func configureIPv6() error {
	if err := setSysctl("net/ipv6/conf/lo/disable_ipv6", "1"); err != nil {
		return err
	}
	if err := setSysctl("net/ipv6/conf/default/addr_gen_mode", "1"); err != nil {
		return err
	}
	if err := setSysctl("net/ipv6/conf/default/autoconf", "0"); err != nil {
		return err
	}
	if err := setSysctl("net/ipv6/conf/default/accept_ra", "0"); err != nil {
		return err
	}
	if err := setSysctl("net/ipv6/conf/all/addr_gen_mode", "1"); err != nil {
		return err
	}
	if err := setSysctl("net/ipv6/conf/all/autoconf", "0"); err != nil {
		return err
	}
	return setSysctl("net/ipv6/conf/all/accept_ra", "0")
}

func setSysctl(path string, value string) error {
	return errors.WithStack(os.WriteFile(filepath.Join("/proc/sys", path), []byte(value), 0o644))
}
