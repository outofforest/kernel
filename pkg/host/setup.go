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
	"strings"
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

	// ErrNotThisHost is an indicator that spec is for different host.
	ErrNotThisHost = errors.New("not this host")

	// ErrHostFound is an indicator that this is the host matching the spec.
	ErrHostFound = errors.New("host found")

	virtPackages = []string{
		"libvirt-daemon-config-network",
		"libvirt-daemon-kvm",
		"qemu-kvm",
		"qemu-virtiofsd",
		"libvirt-nss",
	}

	//go:embed cloudless.repo
	cloudlessRepo []byte
)

// NetworkConfig contains network configuration.
type NetworkConfig struct {
	MAC net.HardwareAddr
	IPs []net.IPNet
}

// ServiceConfig contains service configuration.
type ServiceConfig struct {
	Name   string
	OnExit parallel.OnExit
	TaskFn parallel.Task
}

func newPackageRepo() *packageRepo {
	return &packageRepo{
		packages: map[string]struct{}{},
	}
}

type packageRepo struct {
	packages map[string]struct{}
}

func (pr *packageRepo) Packages() []string {
	packages := make([]string, 0, len(pr.packages))
	for pkg := range pr.packages {
		packages = append(packages, pkg)
	}

	sort.Strings(packages)
	return packages
}

func (pr *packageRepo) Register(packages []string) {
	for _, pkg := range packages {
		pr.packages[pkg] = struct{}{}
	}
}

// PrepareFn is the function type used to register functions preparing host.
type PrepareFn func(ctx context.Context) error

// NewSubconfiguration creates subconfiguration.
func NewSubconfiguration(c *Configuration) (*Configuration, func()) {
	c2 := &Configuration{
		pkgRepo: c.pkgRepo,
	}
	return c2, func() {
		if c2.requireIPForwarding {
			c.RequireIPForwarding()
		}
		if c2.requireInitramfs {
			c.RequireInitramfs()
		}
		if c2.requireVirt {
			c.RequireVirt()
		}
		c.RequireKernelModules(c2.kernelModules...)
		c.RequirePackages(c2.packages...)
		c.SetHostname(c2.hostname)
		if c2.gateway != nil {
			c.SetGateway(c2.gateway)
		}
		c.AddDNSes(c2.dnses...)
		c.AddRepoMirrors(c2.repoMirrors...)
		c.AddNetworks(c2.networks...)
		c.AddFirewallRules(c2.firewall...)
		c.Prepare(c2.prepare...)
		c.StartServices(c2.services...)
	}
}

// Configuration allows service to configure the required host settings.
type Configuration struct {
	pkgRepo *packageRepo

	requireIPForwarding bool
	requireInitramfs    bool
	requireVirt         bool
	kernelModules       []kernel.Module
	packages            []string
	hostname            string
	gateway             net.IP
	dnses               []net.IP
	repoMirrors         []string
	networks            []NetworkConfig
	firewall            []firewall.RuleSource
	prepare             []PrepareFn
	services            []ServiceConfig
}

// RequireIPForwarding is called if host requires IP forwarding to be enabled.
func (c *Configuration) RequireIPForwarding() {
	c.requireIPForwarding = true
}

// RequireInitramfs is called if host requires initramfs to be generated.
func (c *Configuration) RequireInitramfs() {
	c.requireInitramfs = true
}

// RequireVirt is called if host requires virtualization services.
func (c *Configuration) RequireVirt() {
	c.requireVirt = true
	c.pkgRepo.Register(virtPackages)
}

// RequireKernelModules is called to load kernel modules.
func (c *Configuration) RequireKernelModules(kernelModules ...kernel.Module) {
	c.kernelModules = append(c.kernelModules, kernelModules...)
}

// Packages returns the list of packages configured for any host.
func (c *Configuration) Packages() []string {
	return c.pkgRepo.Packages()
}

// RequirePackages is called to install packages.
func (c *Configuration) RequirePackages(packages ...string) {
	c.pkgRepo.Register(packages)
	c.packages = append(c.packages, packages...)
}

// SetHostname sets hostname.
func (c *Configuration) SetHostname(hostname string) {
	c.hostname = hostname
}

// SetGateway sets gateway.
func (c *Configuration) SetGateway(gateway net.IP) {
	c.gateway = gateway
}

// AddDNSes adds DNS servers.
func (c *Configuration) AddDNSes(dnses ...net.IP) {
	c.dnses = append(c.dnses, dnses...)
}

// AddRepoMirrors adds package repository mirrors.
func (c *Configuration) AddRepoMirrors(mirrors ...string) {
	c.repoMirrors = append(c.repoMirrors, mirrors...)
}

// AddNetworks configures networks.
func (c *Configuration) AddNetworks(networks ...NetworkConfig) {
	c.networks = append(c.networks, networks...)
}

// AddFirewallRules add firewall rules.
func (c *Configuration) AddFirewallRules(sources ...firewall.RuleSource) {
	c.firewall = append(c.firewall, sources...)
}

// Prepare adds prepare function to be called.
func (c *Configuration) Prepare(prepares ...PrepareFn) {
	c.prepare = append(c.prepare, prepares...)
}

// StartServices configures services to be started on host.
func (c *Configuration) StartServices(services ...ServiceConfig) {
	c.services = append(c.services, services...)
}

// Configurator is the function called to collect host configuration.
type Configurator func(c *Configuration) error

// Run runs host.
func Run(ctx context.Context, configurators ...Configurator) error {
	if err := mount.Root(); err != nil {
		return err
	}

	cfg := &Configuration{
		pkgRepo: newPackageRepo(),
	}
	var hostFound bool
	for _, c := range configurators {
		err := c(cfg)
		switch {
		case err == nil:
		case errors.Is(err, ErrHostFound):
			if hostFound {
				return errors.New("host matches many configurations")
			}
			hostFound = true
		default:
			return err
		}
	}

	if !hostFound {
		return errors.New("host does not match the configuration")
	}

	ctx = logger.With(ctx, zap.String("host", cfg.hostname))

	if cfg.requireVirt {
		setupVirt(cfg)
	}

	if cfg.requireInitramfs {
		if err := buildInitramfs(); err != nil {
			return err
		}
	}
	if err := removeOldRoot(); err != nil {
		return err
	}
	if err := ConfigureKernelModules(cfg.kernelModules); err != nil {
		return err
	}
	if err := configureDNS(cfg.dnses); err != nil {
		return err
	}
	if err := configureIPv6(); err != nil {
		return err
	}
	if err := configureEnv(cfg.hostname); err != nil {
		return err
	}
	if err := configureHostname(cfg.hostname); err != nil {
		return err
	}
	if err := configureNetworks(cfg.networks); err != nil {
		return err
	}
	if err := configureGateway(cfg.gateway); err != nil {
		return err
	}
	if err := configureFirewall(cfg.firewall); err != nil {
		return err
	}
	if err := installPackages(ctx, cfg.repoMirrors, cfg.packages); err != nil {
		return err
	}
	if cfg.requireVirt {
		if err := pruneVirt(); err != nil {
			return err
		}
	}
	if cfg.requireIPForwarding {
		if err := configureIPForwarding(); err != nil {
			return err
		}
	}
	if err := runPrepares(ctx, cfg.prepare); err != nil {
		return err
	}

	err := runServices(ctx, cfg.services)
	switch {
	case errors.Is(err, ErrPowerOff):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF))
	case errors.Is(err, ErrReboot):
		return errors.WithStack(syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART))
	default:
		return err
	}
}

// ConfigureKernelModules loads kernel modules.
func ConfigureKernelModules(kernelModules []kernel.Module) error {
	for _, m := range kernelModules {
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

func configureNetworks(networks []NetworkConfig) error {
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
				fmt.Println("network configured")
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

func configureNetwork(n NetworkConfig, l netlink.Link) error {
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

	fmt.Println("gateway configured")

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
			if ip.Contains(gateway) {
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

func runPrepares(ctx context.Context, prepare []PrepareFn) error {
	for _, p := range prepare {
		if err := p(ctx); err != nil {
			return err
		}
	}
	return nil
}

func runServices(ctx context.Context, services []ServiceConfig) error {
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

func installPackages(ctx context.Context, repoMirrors, packages []string) error {
	m := map[string]struct{}{}
	for _, p := range packages {
		m[p] = struct{}{}
	}

	if len(m) == 0 {
		return nil
	}

	pkgs := make([]string, 0, len(m))
	for p := range m {
		pkgs = append(pkgs, p)
	}

	sort.Strings(pkgs)

	if err := os.WriteFile("/etc/yum.repos.d/cloudless.mirrors",
		[]byte(strings.Join(repoMirrors, "\n")), 0o600); err != nil {
		return errors.WithStack(err)
	}
	if err := os.WriteFile("/etc/yum.repos.d/cloudless.repo", cloudlessRepo, 0o600); err != nil {
		return errors.WithStack(err)
	}

	// TODO (wojciech): One day I will write an rpm package manager in go.
	return libexec.Exec(ctx, exec.Command("dnf", append(
		[]string{"install", "-y", "--setopt=keepcache=False", "--repo=cloudless"}, pkgs...)...))
}

func configureIPForwarding() error {
	if err := kernel.SetSysctl("net/ipv4/conf/all/forwarding", "1"); err != nil {
		return err
	}
	return errors.WithStack(kernel.SetSysctl("net/ipv6/conf/all/forwarding", "1"))
}

func buildInitramfs() error {
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

func configureFirewall(sources []firewall.RuleSource) error {
	chains, err := firewall.EnsureChains()
	if err != nil {
		return err
	}

	conn := &nftables.Conn{}

	for _, s := range sources {
		rules, err := s(chains)
		if err != nil {
			return err
		}
		for _, r := range rules {
			r.Table = r.Chain.Table
			conn.AddRule(r)
		}
	}
	return errors.WithStack(conn.Flush())
}

func setupVirt(c *Configuration) {
	c.RequirePackages(virtPackages...)
	c.StartServices(ServiceConfig{
		Name:   "virt",
		OnExit: parallel.Fail,
		TaskFn: func(ctx context.Context) error {
			configF, err := os.OpenFile("/etc/libvirt/qemu.conf", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				return errors.WithStack(err)
			}
			defer configF.Close()

			if _, err := configF.WriteString("\nuser = \"root\"\ngroup = \"root\"\n"); err != nil {
				return errors.WithStack(err)
			}

			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				for _, c := range []string{"virtqemud", "virtlogd", "virtstoraged", "virtnetworkd", "virtnodedevd"} {
					spawn(c, parallel.Fail, func(ctx context.Context) error {
						return libexec.Exec(ctx, exec.Command(filepath.Join("/usr/sbin", c)))
					})
				}

				return nil
			})
		},
	})
}

func pruneVirt() error {
	return errors.WithStack(filepath.WalkDir("/etc/libvirt/qemu", func(path string, d os.DirEntry, err error) error {
		if !d.IsDir() {
			return os.Remove(path)
		}
		return nil
	}))
}
