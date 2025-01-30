package main

import (
	. "github.com/outofforest/cloudless" //nolint:stylecheck
	"github.com/outofforest/cloudless/pkg/acpi"
	containercache "github.com/outofforest/cloudless/pkg/container/cache"
	"github.com/outofforest/cloudless/pkg/dns"
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
	RepoMirrors("http://10.0.0.100"),
	acpi.PowerService(),
	ntp.Service(),
	ssh.Service("AAAAC3NzaC1lZDI1NTE5AAAAIEcJvvtOBgTsm3mq3Sg8cjn6Mz/vC9f3k6a89ZOjIyF6"),
	Host("pxe",
		Gateway("10.0.0.1"),
		Network("00:01:0a:00:00:05", "10.0.0.100/24", "fe80::1/10"),
		pxe.Service("/dev/sda"),
		yum.Service("/tmp/repo-fedora"),
		containercache.Service("/tmp/repo-containers",
			"ghcr.io/letsencrypt/pebble@sha256:6d78e2b981c77b16e07a2344fb1e0a0beb420af0246816df6810503a2fe74b1b",
			"fedora@sha256:9cfb3a7ad0a36a1e943409def613ec495571a5683c45addb5d608c2c29bb8248",
			"grafana/grafana@sha256:58aeabeae706b990b3b1fc5ae8c97fd131921b2d6eb26a137ebaa91689d6ebfe",
			"grafana/loki@sha256:1a69e8f87e97bb1782880b423e4961a8a9d9afead673c8d92c7dcc477d3d4448",
			"prom/prometheus@sha256:c4c1af714765bd7e06e7ae8301610c9244686a4c02d5329ae275878e10eb481b",
		),
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
	Host("demo",
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
	Host("vm",
		Gateway("10.0.1.1"),
		Network("00:01:0a:00:02:05", "10.0.1.2/24"),
	),
)

func main() {
	Main(deployment...)
}
