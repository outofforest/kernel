package host

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/cavaliergopher/cpio"
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

	//go:embed cloudless.repo
	cloudlessRepo []byte
)

// Configurator allows service to configure the required host settings.
type Configurator struct {
	mu     sync.Mutex
	chains firewall.Chains
}

// AddFirewallRules add firewall rules.
func (c *Configurator) AddFirewallRules(sources ...firewall.RuleSource) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn := &nftables.Conn{}

	for _, s := range sources {
		for _, r := range s(c.chains) {
			r.Table = r.Chain.Table
			conn.AddRule(r)
		}
	}
	return errors.WithStack(conn.Flush())
}

// Config contains configuration.
type Config struct {
	KernelModules []kernel.Module
	DNS           []net.IP
	Services      []Service
	Hosts         map[string]Host
}

// Host contains host configuration.
type Host struct {
	Gateway  net.IP
	Networks []Network
	Services []Service
}

// Network contains network configuration.
type Network struct {
	MAC net.HardwareAddr
	IPs []net.IPNet
}

// Service contains service configuration.
type Service struct {
	Name                 string
	OnExit               parallel.OnExit
	RequiresIPForwarding bool
	RequiresInitramfs    bool
	KernelModules        []kernel.Module
	Packages             []string
	Firewall             []firewall.RuleSource
	ServiceFn            func(ctx context.Context, configurator *Configurator) error
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

	if err := configureDNS(config.DNS); err != nil {
		return err
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
		for hn, hc := range config.Hosts {
			for _, n := range hc.Networks {
				if bytes.Equal(n.MAC, hwAddr) {
					return runHost(ctx, hn, config)
				}
			}
		}
	}

	return errors.Errorf("no matching link found")
}

func runHost(ctx context.Context, hostname string, config Config) error {
	ctx = logger.With(ctx, zap.String("host", hostname))
	h := config.Hosts[hostname]
	services := append(append([]Service{}, config.Services...), h.Services...)

	if err := buildInitramfs(services); err != nil {
		return err
	}
	if err := removeOldRoot(); err != nil {
		return err
	}
	if err := configureEnv(hostname); err != nil {
		return err
	}
	if err := configureHostname(hostname); err != nil {
		return err
	}
	if err := configureKernelModules(services); err != nil {
		return err
	}

	if err := configureNetworks(h.Networks); err != nil {
		return err
	}
	if err := configureGateway(h.Gateway); err != nil {
		return err
	}
	if err := installPackages(ctx, services); err != nil {
		return err
	}
	if err := configureIPForwarding(services); err != nil {
		return err
	}

	chains, err := firewall.EnsureChains()
	if err != nil {
		return err
	}
	configurator := &Configurator{
		chains: chains,
	}

	err = runServices(ctx, configurator, services)
	switch {
	case errors.Is(err, ErrPowerOff):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF))
	case errors.Is(err, ErrReboot):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART))
	default:
		return err
	}
}

func configureKernelModules(services []Service) error {
	for _, s := range services {
		for _, m := range s.KernelModules {
			if err := kernel.LoadModule(m); err != nil {
				return err
			}
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
	if err := kernel.SetSysctl("net/ipv6/conf/lo/disable_ipv6", "1"); err != nil {
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

	if !ip6Found {
		if err := kernel.SetSysctl(filepath.Join("net/ipv6/conf", lName, "disable_ipv6"), "1"); err != nil {
			return err
		}
	}

	return nil
}

func configureGateway(gateway net.IP) error {
	if gateway == nil {
		return nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		return errors.WithStack(err)
	}
	for _, l := range links {
		ips, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return errors.WithStack(err)
		}
		for _, ip := range ips {
			if bytes.Equal(ip.IP.Mask(ip.Mask).To4(), gateway.Mask(ip.Mask).To4()) {
				return errors.WithStack(netlink.RouteAdd(&netlink.Route{
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: l.Attrs().Index,
					Gw:        gateway,
				}))
			}
		}
	}

	return errors.Errorf("no link found for gateway %q", gateway)
}

func configureIPv6OnInterface(lName string) error {
	if err := kernel.SetSysctl(filepath.Join("net/ipv6/conf", lName, "autoconf"), "0"); err != nil {
		return err
	}
	if err := kernel.SetSysctl(filepath.Join("net/ipv6/conf", lName, "accept_ra"), "0"); err != nil {
		return err
	}
	return kernel.SetSysctl(filepath.Join("net/ipv6/conf", lName, "addr_gen_mode"), "1")
}

func configureIPv6() error {
	if err := kernel.SetSysctl("net/ipv6/conf/default/addr_gen_mode", "1"); err != nil {
		return err
	}
	if err := kernel.SetSysctl("net/ipv6/conf/default/autoconf", "0"); err != nil {
		return err
	}
	if err := kernel.SetSysctl("net/ipv6/conf/default/accept_ra", "0"); err != nil {
		return err
	}
	if err := kernel.SetSysctl("net/ipv6/conf/all/addr_gen_mode", "1"); err != nil {
		return err
	}
	if err := kernel.SetSysctl("net/ipv6/conf/all/autoconf", "0"); err != nil {
		return err
	}
	return kernel.SetSysctl("net/ipv6/conf/all/accept_ra", "0")
}

func runServices(ctx context.Context, configurator *Configurator, services []Service) error {
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
					if err := configurator.AddFirewallRules(s.Firewall...); err != nil {
						return err
					}

					spawn(s.Name, s.OnExit, func(ctx context.Context) error {
						ctx = logger.With(ctx, zap.String("service", s.Name))
						log := logger.Get(ctx)

						log.Info("Starting service")
						defer log.Info("Service stopped")

						return s.ServiceFn(ctx, configurator)
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

func installPackages(ctx context.Context, services []Service) error {
	m := map[string]struct{}{}
	for _, s := range services {
		for _, p := range s.Packages {
			m[p] = struct{}{}
		}
	}

	if len(m) == 0 {
		return nil
	}

	packages := make([]string, 0, len(m))
	for p := range m {
		packages = append(packages, p)
	}

	sort.Strings(packages)

	if err := os.WriteFile("/etc/yum.repos.d/cloudless.mirrors",
		[]byte("http://10.0.0.100\n"), 0o600); err != nil {
		return errors.WithStack(err)
	}
	if err := os.WriteFile("/etc/yum.repos.d/cloudless.repo", cloudlessRepo, 0o600); err != nil {
		return errors.WithStack(err)
	}

	// TODO (wojciech): One day I will write an rpm package manager in go.
	return libexec.Exec(ctx, exec.Command("dnf", append(
		[]string{"install", "-y", "--setopt=keepcache=False", "--repo=cloudless"}, packages...)...))
}

func configureIPForwarding(services []Service) error {
	for _, s := range services {
		if !s.RequiresIPForwarding {
			continue
		}

		if err := kernel.SetSysctl("net/ipv4/conf/all/forwarding", "1"); err != nil {
			return err
		}
		return errors.WithStack(kernel.SetSysctl("net/ipv6/conf/all/forwarding", "1"))
	}

	return nil
}

func buildInitramfs(services []Service) error {
	for _, s := range services {
		if !s.RequiresInitramfs {
			continue
		}

		if err := os.MkdirAll("/boot", 0o555); err != nil {
			return errors.WithStack(err)
		}
		dF, err := os.OpenFile("/boot/initramfs", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.WithStack(err)
		}
		defer dF.Close()

		cW := gzip.NewWriter(dF)
		defer cW.Close()

		w := cpio.NewWriter(cW)
		defer w.Close()

		if err := addFile(w, 0o600, "/oldroot/initramfs.tar"); err != nil {
			return err
		}
		return addFile(w, 0o700, "/oldroot/init")
	}

	return nil
}

func addFile(w *cpio.Writer, mode cpio.FileMode, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return errors.WithStack(err)
	}

	if err := w.WriteHeader(&cpio.Header{
		Name: filepath.Base(file),
		Size: size,
		Mode: mode,
	}); err != nil {
		return errors.WithStack(err)
	}

	_, err = io.Copy(w, f)
	return errors.WithStack(err)
}

func removeOldRoot() error {
	items, err := os.ReadDir("/oldroot")
	if err != nil {
		return errors.WithStack(err)
	}
	for _, item := range items {
		if err := os.RemoveAll(filepath.Join("/oldroot", item.Name())); err != nil {
			return errors.WithStack(err)
		}
	}
	if err := syscall.Unmount("/oldroot", 0); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(os.RemoveAll("/oldroot"))
}
