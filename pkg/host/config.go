package host

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/host/zombie"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/mount"
	"github.com/outofforest/libexec"
	"github.com/outofforest/logger"
	"github.com/outofforest/parallel"
)

var (
	// ErrPowerOff means that host should be powered off.
	ErrPowerOff = errors.New("power off requested")

	// ErrReboot means that host should be rebooted.
	ErrReboot = errors.New("reboot requested")
)

// Config contains configuration.
type Config struct {
	KernelModules []string
	Hosts         []Host
}

// Host contains host configuration.
type Host struct {
	Hostname      string
	KernelModules []string
	Networks      []Network
	DNS           []net.IP
	Packages      []string
	Firewall      []firewall.RuleSource
	Services      []Service
}

// Network contains network configuration.
type Network struct {
	MAC     net.HardwareAddr
	IPs     []net.IPNet
	Gateway net.IP
}

// Service contains service configuration.
type Service struct {
	Name   string
	OnExit parallel.OnExit
	TaskFn parallel.Task
}

// Run runs host system.
func Run(ctx context.Context, config Config) error {
	if err := mount.Root(); err != nil {
		return err
	}
	for _, m := range config.KernelModules {
		if err := kernel.LoadModule(m); err != nil {
			return err
		}
	}

	if err := configureIPv6(); err != nil {
		return err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, l := range links {
		hwAddr := l.Attrs().HardwareAddr
		for _, hc := range config.Hosts {
			for _, n := range hc.Networks {
				if bytes.Equal(n.MAC, hwAddr) {
					return runHost(ctx, hc)
				}
			}
		}
	}

	return errors.Errorf("no matching link found")
}

func runHost(ctx context.Context, h Host) error {
	ctx = logger.With(ctx, zap.String("host", h.Hostname))

	if err := configureEnv(h.Hostname); err != nil {
		return err
	}
	if err := configureHostname(h.Hostname); err != nil {
		return err
	}
	if err := configureKernelModules(h.KernelModules); err != nil {
		return err
	}
	if err := configureFirewall(h.Firewall); err != nil {
		return err
	}
	if err := configureDNS(h.DNS); err != nil {
		return err
	}
	if err := configureNetworks(h.Networks); err != nil {
		return err
	}
	if err := installPackages(ctx, h.Packages); err != nil {
		return err
	}

	err := runServices(ctx, h.Services)
	switch {
	case errors.Is(err, ErrPowerOff):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF))
	case errors.Is(err, ErrReboot):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART))
	default:
		return err
	}
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
	if err := configureLoopback(); err != nil {
		return err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, n := range networks {
		var found bool
		for _, l := range links {
			if bytes.Equal(n.MAC, l.Attrs().HardwareAddr) {
				if err := configureNetwork(n, l); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return errors.Errorf("link %s not found", n.MAC)
		}
	}

	return nil
}

func configureLoopback() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return errors.WithStack(err)
	}
	if err := setSysctl("net/ipv6/conf/lo/disable_ipv6", "1"); err != nil {
		return err
	}
	return errors.WithStack(netlink.LinkSetUp(lo))
}

func configureNetwork(n Network, l netlink.Link) error {
	lName := l.Attrs().Name
	if err := configureIPv6OnInterface(lName); err != nil {
		return err
	}

	var ip6Found bool
	for _, ip := range n.IPs {
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

	if n.Gateway != nil {
		if err := netlink.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: l.Attrs().Index,
			Gw:        n.Gateway,
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

func runServices(ctx context.Context, services []Service) error {
	if len(services) == 0 {
		return errors.New("no services defined")
	}

	return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		appTerminatedCh := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGCHLD)

		spawn("zombie", parallel.Fail, func(ctx context.Context) error {
			return zombie.Run(ctx, sigCh, appTerminatedCh)
		})
		spawn("services", parallel.Exit, func(ctx context.Context) error {
			defer close(appTerminatedCh)

			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				for _, s := range services {
					spawn(s.Name, s.OnExit, func(ctx context.Context) error {
						ctx = logger.With(ctx, zap.String("service", s.Name))
						log := logger.Get(ctx)

						log.Info("Starting service")
						defer log.Info("Service stopped")

						return s.TaskFn(ctx)
					})
				}
				return nil
			})
		})

		return nil
	})
}

func configureEnv(hostname string) error {
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return errors.WithStack(err)
	}

	for k, v := range map[string]string{
		"PATH":     "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin",
		"HOME":     "/root",
		"USER":     "root",
		"TERM":     "xterm-256color",
		"HOSTNAME": hostname,
	} {
		if err := os.Setenv(k, v); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func configureFirewall(sources []firewall.RuleSource) error {
	c := &nftables.Conn{}
	chains := firewall.EnsureChains(c)

	for _, s := range sources {
		for _, r := range s(chains) {
			r.Table = r.Chain.Table
			c.AddRule(r)
		}
	}

	return errors.WithStack(c.Flush())
}

func installPackages(ctx context.Context, packages []string) error {
	if len(packages) == 0 {
		return nil
	}

	// TODO (wojciech): One day I will write an rpm package manager in go.
	return libexec.Exec(ctx, exec.Command("dnf", append(
		[]string{"install", "--refresh", "-y", "--setopt=keepcache=False"},
		packages...,
	)...))
}
