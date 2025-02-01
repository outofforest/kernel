package main

import (
	"path/filepath"

	. "github.com/outofforest/cloudless" //nolint:stylecheck
	"github.com/outofforest/cloudless/pkg/acpi"
	"github.com/outofforest/cloudless/pkg/cnet"
	"github.com/outofforest/cloudless/pkg/container"
	containercache "github.com/outofforest/cloudless/pkg/container/cache"
	"github.com/outofforest/cloudless/pkg/dns"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/ntp"
	"github.com/outofforest/cloudless/pkg/pxe"
	"github.com/outofforest/cloudless/pkg/ssh"
	"github.com/outofforest/cloudless/pkg/vm"
	"github.com/outofforest/cloudless/pkg/vnet"
	"github.com/outofforest/cloudless/pkg/yum"
)

var deployment = Deployment(
	ImmediateKernelModules(DefaultKernelModules...),
	DNS(DefaultDNS...),
	YumMirrors("http://10.0.0.100"),
	ContainerMirrors("http://10.0.0.100:81"),
	acpi.PowerService(),
	ntp.Service(),
	ssh.Service("AAAAC3NzaC1lZDI1NTE5AAAAIEcJvvtOBgTsm3mq3Sg8cjn6Mz/vC9f3k6a89ZOjIyF6"),
	Box("pxe",
		Gateway("10.0.0.1"),
		Network("00:01:0a:00:00:05", "10.0.0.100/24", "fe80::1/10"),
		pxe.Service("/dev/sda"),
		yum.Service("/tmp/repo-fedora"),
		containercache.Service("/tmp/repo-containers"),
		dns.Service(
			dns.ForwardTo("1.1.1.1", "8.8.8.8"),
			dns.ForwardFor("10.0.0.0/24"),
			dns.Zone("exw.co", "ns1.exw.co", "wojtek@exw.co", 1,
				dns.Nameservers("ns1.exw.co", "ns2.exw.co"),
				dns.Domain("ns1.exw.co", "127.0.0.1"),
				dns.Domain("ns2.exw.co", "127.0.0.2"),
				dns.Domain("exw.co", "127.0.0.3"),
				dns.Domain("test.exw.co", "127.0.0.5", "127.0.0.6", "127.0.0.7"),
				dns.Domain("mail.exw.co", "127.0.0.8"),
				dns.Alias("alias.exw.co", "exw.co"),
				dns.Alias("lala.alias.exw.co", "alias.exw.co"),
				dns.Text("exw.co", "text1", "text2"),
				dns.MailExchange("mail.exw.co", 10),
				dns.MailExchange("mail2.exw.co", 20),
			),
		),
	),
	Box("demo",
		Gateway("10.0.0.1"),
		Network("00:01:0a:00:00:9b", "10.0.0.155/24"),
		vnet.NAT("internal", "52:54:00:6d:94:c0",
			vnet.IP4("10.0.1.1/24"),
			vnet.IP6("fdff:8ffd:d676::1/64"),
		),
		vm.New("vm", 5, 4,
			vm.Network("internal", "00:01:0a:00:02:05"),
		),
	),
	Box("vm",
		Gateway("10.0.1.1"),
		Network("00:01:0a:00:02:05", "10.0.1.2/24"),
		cnet.NAT("monitoring",
			cnet.IP4("10.0.2.1/24"),
		),
		container.New("grafana",
			container.Network("monitoring", "52:54:00:6e:94:c0"),
		),
	),
	Box("grafana",
		Gateway("10.0.2.1"),
		Network("52:54:00:6e:94:c0", "10.0.2.2/24"),
		Firewall(firewall.OpenV4TCPPort(80)),
		container.AppMount("/tmp/app/grafana"),
		container.RunImage(
			"grafana/grafana@sha256:58aeabeae706b990b3b1fc5ae8c97fd131921b2d6eb26a137ebaa91689d6ebfe",
			container.EnvVar("GF_USERS_ALLOW_SIGN_UP", "false"),
			container.EnvVar("GF_PATHS_PROVISIONING", filepath.Join(container.AppDir, "provisioning")),
			container.EnvVar("GF_PATHS_DATA", filepath.Join(container.AppDir, "data")),
			container.EnvVar("GF_SERVER_HTTP_PORT", "80"),
			container.EnvVar("GF_LOG_MODE", "console"),
			container.EnvVar("GF_LOG_CONSOLE_LEVEL", "info"),
			container.EnvVar("GF_LOG_CONSOLE_FORMAT", "json"),
		),
	),
)

func main() {
	Main(deployment...)
}
