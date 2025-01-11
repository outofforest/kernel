package main

import (
	. "github.com/outofforest/cloudless" //nolint:stylecheck
	"github.com/outofforest/cloudless/pkg/acpi"
	"github.com/outofforest/cloudless/pkg/ntp"
	"github.com/outofforest/cloudless/pkg/pxe"
	"github.com/outofforest/cloudless/pkg/ssh"
	"github.com/outofforest/cloudless/pkg/virt"
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
		yum.Service("/tmp/repo"),
	),
	Host("demo",
		Gateway("10.0.0.1"),
		Network("00:01:0a:00:00:9b", "10.0.0.155/24"),
		virt.NATedNetwork(),
		virt.VM(),
	),
	Host("vm",
		Gateway("10.0.1.1"),
		Network("00:01:0a:00:02:05", "10.0.1.2/24"),
	),
)

func main() {
	Main(deployment...)
}
